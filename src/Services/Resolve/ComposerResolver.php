<?php

namespace Dgtlss\Warden\Services\Resolve;

use Dgtlss\Warden\Data\ResolutionPlanItem;
use Dgtlss\Warden\Services\ProcessRunner;

class ComposerResolver implements FindingResolverInterface
{
    public function __construct(protected ProcessRunner $runner)
    {
    }

    public function supports(array $finding, array $options = []): bool
    {
        if (!(bool) config('warden.resolve.package_managers.composer', true)) {
            return false;
        }

        return ($finding['resolver_type'] ?? null) === 'composer'
            || (($finding['source'] ?? null) === 'composer' && ($finding['category'] ?? null) === 'dependency');
    }

    public function plan(array $finding, array $options = []): ?ResolutionPlanItem
    {
        if (!$this->supports($finding, $options)) {
            return null;
        }

        $package = (string) ($finding['package'] ?? 'composer');
        $ruleId = (string) ($finding['rule_id'] ?? 'composer.resolve');
        $title = (string) ($finding['title'] ?? 'Composer dependency issue');
        $isDirect = (bool) ($finding['is_direct_dependency'] ?? false);
        $isDev = (bool) ($finding['is_dev_dependency'] ?? false);
        $declaredConstraint = isset($finding['declared_constraint']) && is_string($finding['declared_constraint'])
            ? $finding['declared_constraint']
            : null;
        $installedVersion = isset($finding['installed_version']) && is_string($finding['installed_version'])
            ? $finding['installed_version']
            : null;
        $replacement = isset($finding['replacement']) && is_string($finding['replacement']) && $finding['replacement'] !== ''
            ? $finding['replacement']
            : null;

        if ($isDev && !($options['with_dev'] ?? false)) {
            return $this->manualItem(
                package: $package,
                title: $title,
                ruleIds: [$ruleId],
                strategy: (string) ($finding['resolution_strategy'] ?? 'update-package'),
                reason: 'This issue affects a development dependency. Re-run with --with-dev to include development package updates.',
                metadata: $finding,
            );
        }

        if (($finding['resolution_strategy'] ?? null) === 'abandoned-replace') {
            if (!$isDirect || $replacement === null) {
                return $this->manualItem(
                    package: $package,
                    title: $title,
                    ruleIds: [$ruleId],
                    strategy: 'abandoned-replace',
                    reason: 'Automatic replacement is only supported when the abandoned package is a direct dependency and Composer provides an explicit replacement.',
                    metadata: $finding,
                );
            }

            return new ResolutionPlanItem(
                id: 'composer-replace-' . md5($package . $replacement),
                source: 'composer',
                package: $package,
                title: sprintf('Replace abandoned package %s with %s', $package, $replacement),
                ruleIds: [$ruleId],
                commands: [
                    [
                        'command' => ['composer', 'remove', $package, '--no-interaction'],
                        'display' => sprintf('composer remove %s --no-interaction', $package),
                    ],
                    [
                        'command' => ['composer', 'require', $replacement, '--no-interaction'],
                        'display' => sprintf('composer require %s --no-interaction', $replacement),
                    ],
                ],
                expectedFiles: ['composer.json', 'composer.lock'],
                riskLevel: 'review',
                requiresNetwork: true,
                verificationSteps: $this->verificationSteps(),
                strategy: 'abandoned-replace',
                metadata: array_merge($finding, [
                    'replacement' => $replacement,
                ]),
            );
        }

        if ($isDirect) {
            if ($declaredConstraint !== null && $this->looksPinned($declaredConstraint)) {
                return new ResolutionPlanItem(
                    id: 'composer-pinned-' . md5($package . $ruleId),
                    source: 'composer',
                    package: $package,
                    title: sprintf('Review pinned Composer constraint for %s', $package),
                    ruleIds: [$ruleId],
                    commands: [],
                    expectedFiles: ['composer.json', 'composer.lock'],
                    riskLevel: 'high-risk',
                    requiresNetwork: true,
                    verificationSteps: $this->verificationSteps(),
                    strategy: 'constraint-review',
                    actionable: false,
                    reason: 'The root version constraint appears pinned and may require a manual constraint change before Composer can install a patched release.',
                    metadata: array_merge($finding, [
                        'declared_constraint' => $declaredConstraint,
                        'installed_version' => $installedVersion,
                    ]),
                );
            }

            return new ResolutionPlanItem(
                id: 'composer-update-' . md5($package),
                source: 'composer',
                package: $package,
                title: sprintf('Update Composer package %s', $package),
                ruleIds: [$ruleId],
                commands: [[
                    'command' => ['composer', 'update', $package, '--with-all-dependencies', '--no-interaction'],
                    'display' => sprintf('composer update %s --with-all-dependencies --no-interaction', $package),
                ]],
                expectedFiles: ['composer.lock'],
                riskLevel: 'safe',
                requiresNetwork: true,
                verificationSteps: $this->verificationSteps(),
                strategy: 'update-package',
                metadata: array_merge($finding, [
                    'declared_constraint' => $declaredConstraint,
                    'installed_version' => $installedVersion,
                ]),
            );
        }

        $directParent = $this->determineDirectParent($package);

        if ($directParent !== null) {
            return new ResolutionPlanItem(
                id: 'composer-parent-update-' . md5($package . $directParent),
                source: 'composer',
                package: $package,
                title: sprintf('Update direct dependency path for transitive package %s via %s', $package, $directParent),
                ruleIds: [$ruleId],
                commands: [[
                    'command' => ['composer', 'update', $directParent, '--with-all-dependencies', '--no-interaction'],
                    'display' => sprintf('composer update %s --with-all-dependencies --no-interaction', $directParent),
                ]],
                expectedFiles: ['composer.lock'],
                riskLevel: 'review',
                requiresNetwork: true,
                verificationSteps: $this->verificationSteps(),
                strategy: 'update-dependency-path',
                metadata: array_merge($finding, [
                    'direct_parent' => $directParent,
                ]),
            );
        }

        return $this->manualItem(
            package: $package,
            title: $title,
            ruleIds: [$ruleId],
            strategy: 'manual-review',
            reason: 'The vulnerable package is transitive and Warden could not determine a single direct dependency path to update safely.',
            metadata: $finding,
        );
    }

    /**
     * @return array<int, string>
     */
    protected function verificationSteps(): array
    {
        return [
            'composer phpstan',
            'vendor/bin/phpunit tests/',
            'warden:audit --no-notify',
        ];
    }

    protected function looksPinned(string $constraint): bool
    {
        return !str_contains($constraint, '^')
            && !str_contains($constraint, '~')
            && !str_contains($constraint, '*')
            && !str_contains($constraint, '>')
            && !str_contains($constraint, '<')
            && !str_contains($constraint, '|');
    }

    protected function determineDirectParent(string $package): ?string
    {
        if (!file_exists(base_path('composer.json'))) {
            return null;
        }

        $result = $this->runner->run(
            ['composer', 'why', $package, '--no-interaction', '--no-ansi'],
            base_path(),
            60
        );

        if (!$result->isSuccessful()) {
            return null;
        }

        $rootRequirements = $this->rootRequirements();
        $parents = [];

        foreach (preg_split('/\R/', $result->stdout) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, 'There is no')) {
                continue;
            }

            if (preg_match('/^([^\s]+)\s+/', $line, $matches) !== 1) {
                continue;
            }

            $parent = $matches[1];
            if ($parent === $package) {
                continue;
            }

            if (isset($rootRequirements[$parent])) {
                $parents[] = $parent;
            }
        }

        $parents = array_values(array_unique($parents));

        return count($parents) === 1 ? $parents[0] : null;
    }

    /**
     * @return array<string, bool>
     */
    protected function rootRequirements(): array
    {
        $contents = file_get_contents(base_path('composer.json'));
        if ($contents === false) {
            return [];
        }

        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            return [];
        }

        $requirements = [];

        foreach (['require', 'require-dev'] as $key) {
            if (!isset($decoded[$key]) || !is_array($decoded[$key])) {
                continue;
            }

            foreach (array_keys($decoded[$key]) as $package) {
                if (is_string($package)) {
                    $requirements[$package] = true;
                }
            }
        }

        return $requirements;
    }

    /**
     * @param array<int, string> $ruleIds
     * @param array<string, mixed> $metadata
     */
    protected function manualItem(
        string $package,
        string $title,
        array $ruleIds,
        string $strategy,
        string $reason,
        array $metadata,
    ): ResolutionPlanItem {
        return new ResolutionPlanItem(
            id: 'composer-manual-' . md5($package . implode('|', $ruleIds)),
            source: 'composer',
            package: $package,
            title: $title,
            ruleIds: $ruleIds,
            commands: [],
            expectedFiles: ['composer.json', 'composer.lock'],
            riskLevel: 'review',
            requiresNetwork: true,
            verificationSteps: $this->verificationSteps(),
            strategy: $strategy,
            actionable: false,
            reason: $reason,
            metadata: $metadata,
        );
    }
}
