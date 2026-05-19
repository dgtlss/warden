<?php

namespace Dgtlss\Warden\Services\Resolve;

use Dgtlss\Warden\Data\ResolutionPlanItem;
use Dgtlss\Warden\Services\ProcessRunner;

class JavascriptResolver implements FindingResolverInterface
{
    public function __construct(protected ProcessRunner $runner)
    {
    }

    public function supports(array $finding, array $options = []): bool
    {
        $manager = (string) ($finding['package_manager'] ?? 'npm');
        if (!(bool) config('warden.resolve.package_managers.' . $manager, true)) {
            return false;
        }

        return ($finding['resolver_type'] ?? null) === 'javascript'
            || (($finding['source'] ?? null) === 'npm' && ($finding['category'] ?? null) === 'dependency');
    }

    public function plan(array $finding, array $options = []): ?ResolutionPlanItem
    {
        if (!$this->supports($finding, $options)) {
            return null;
        }

        $package = (string) ($finding['package'] ?? 'npm');
        $manager = (string) ($finding['package_manager'] ?? 'npm');
        $ruleId = (string) ($finding['rule_id'] ?? 'javascript.resolve');
        $title = (string) ($finding['title'] ?? 'JavaScript dependency issue');
        $isDirect = (bool) ($finding['is_direct_dependency'] ?? false);
        $isDev = (bool) ($finding['is_dev_dependency'] ?? false);

        if ($isDev && !($options['with_dev'] ?? false)) {
            return $this->manualItem(
                manager: $manager,
                package: $package,
                title: $title,
                ruleIds: [$ruleId],
                strategy: 'update-package',
                reason: 'This issue affects a development dependency. Re-run with --with-dev to include development package updates.',
                metadata: $finding,
            );
        }

        if (!$this->runner->commandExists($manager)) {
            return $this->manualItem(
                manager: $manager,
                package: $package,
                title: $title,
                ruleIds: [$ruleId],
                strategy: 'manager-missing',
                reason: sprintf('The %s binary is not available locally, so Warden cannot apply this resolution automatically.', $manager),
                metadata: $finding,
            );
        }

        $lockfile = isset($finding['lockfile']) && is_string($finding['lockfile']) ? $finding['lockfile'] : 'package-lock.json';

        if ($manager === 'npm') {
            if ($isDirect) {
                $constraint = isset($finding['declared_constraint']) && is_string($finding['declared_constraint'])
                    ? $finding['declared_constraint']
                    : null;

                if ($constraint !== null && $this->looksPinned($constraint)) {
                    return new ResolutionPlanItem(
                        id: 'npm-major-' . md5($package),
                        source: 'npm',
                        package: $package,
                        title: sprintf('Review major npm upgrade for %s', $package),
                        ruleIds: [$ruleId],
                        commands: [[
                            'command' => ['npm', 'install', sprintf('%s@latest', $package)],
                            'display' => sprintf('npm install %s@latest', $package),
                        ]],
                        expectedFiles: [$lockfile, 'package.json'],
                        riskLevel: 'high-risk',
                        requiresNetwork: true,
                        verificationSteps: $this->verificationSteps(),
                        strategy: 'major-update',
                        metadata: $finding,
                    );
                }

                return new ResolutionPlanItem(
                    id: 'npm-update-' . md5($package),
                    source: 'npm',
                    package: $package,
                    title: sprintf('Update JavaScript package %s', $package),
                    ruleIds: [$ruleId],
                    commands: [[
                        'command' => ['npm', 'update', $package],
                        'display' => sprintf('npm update %s', $package),
                    ]],
                    expectedFiles: [$lockfile, 'package.json'],
                    riskLevel: 'review',
                    requiresNetwork: true,
                    verificationSteps: $this->verificationSteps(),
                    strategy: 'update-package',
                    metadata: $finding,
                );
            }

            return new ResolutionPlanItem(
                id: 'npm-audit-fix-' . md5($package . $ruleId),
                source: 'npm',
                package: $package,
                title: sprintf('Refresh npm lockfile for transitive issue in %s', $package),
                ruleIds: [$ruleId],
                commands: [[
                    'command' => ['npm', 'audit', 'fix', '--package-lock-only'],
                    'display' => 'npm audit fix --package-lock-only',
                ]],
                expectedFiles: [$lockfile],
                riskLevel: 'review',
                requiresNetwork: true,
                verificationSteps: $this->verificationSteps(),
                strategy: 'audit-fix',
                metadata: $finding,
            );
        }

        if ($manager === 'pnpm' && $isDirect) {
            $constraint = isset($finding['declared_constraint']) && is_string($finding['declared_constraint'])
                ? $finding['declared_constraint']
                : null;

            if ($constraint !== null && $this->looksPinned($constraint)) {
                return new ResolutionPlanItem(
                    id: 'pnpm-major-' . md5($package),
                    source: 'npm',
                    package: $package,
                    title: sprintf('Review major pnpm upgrade for %s', $package),
                    ruleIds: [$ruleId],
                    commands: [[
                        'command' => ['pnpm', 'up', sprintf('%s@latest', $package)],
                        'display' => sprintf('pnpm up %s@latest', $package),
                    ]],
                    expectedFiles: [$lockfile, 'package.json'],
                    riskLevel: 'high-risk',
                    requiresNetwork: true,
                    verificationSteps: $this->verificationSteps(),
                    strategy: 'major-update',
                    metadata: $finding,
                );
            }

            return new ResolutionPlanItem(
                id: 'pnpm-up-' . md5($package),
                source: 'npm',
                package: $package,
                title: sprintf('Update pnpm dependency %s', $package),
                ruleIds: [$ruleId],
                commands: [[
                    'command' => ['pnpm', 'up', $package],
                    'display' => sprintf('pnpm up %s', $package),
                ]],
                expectedFiles: [$lockfile, 'package.json'],
                riskLevel: 'review',
                requiresNetwork: true,
                verificationSteps: $this->verificationSteps(),
                strategy: 'update-package',
                metadata: $finding,
            );
        }

        if ($manager === 'yarn' && $isDirect) {
            $constraint = isset($finding['declared_constraint']) && is_string($finding['declared_constraint'])
                ? $finding['declared_constraint']
                : null;

            if ($constraint !== null && $this->looksPinned($constraint)) {
                return new ResolutionPlanItem(
                    id: 'yarn-major-' . md5($package),
                    source: 'npm',
                    package: $package,
                    title: sprintf('Review major Yarn upgrade for %s', $package),
                    ruleIds: [$ruleId],
                    commands: [[
                        'command' => ['yarn', 'up', sprintf('%s@latest', $package)],
                        'display' => sprintf('yarn up %s@latest', $package),
                    ]],
                    expectedFiles: [$lockfile, 'package.json'],
                    riskLevel: 'high-risk',
                    requiresNetwork: true,
                    verificationSteps: $this->verificationSteps(),
                    strategy: 'major-update',
                    metadata: $finding,
                );
            }

            return new ResolutionPlanItem(
                id: 'yarn-up-' . md5($package),
                source: 'npm',
                package: $package,
                title: sprintf('Update Yarn dependency %s', $package),
                ruleIds: [$ruleId],
                commands: [[
                    'command' => ['yarn', 'up', $package],
                    'display' => sprintf('yarn up %s', $package),
                ]],
                expectedFiles: [$lockfile, 'package.json'],
                riskLevel: 'review',
                requiresNetwork: true,
                verificationSteps: $this->verificationSteps(),
                strategy: 'update-package',
                metadata: $finding,
            );
        }

        return $this->manualItem(
            manager: $manager,
            package: $package,
            title: $title,
            ruleIds: [$ruleId],
            strategy: 'manual-review',
            reason: 'Warden can only apply deterministic JavaScript fixes automatically for direct dependencies or npm lockfile refreshes in v1.',
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

    /**
     * @param array<int, string> $ruleIds
     * @param array<string, mixed> $metadata
     */
    protected function manualItem(
        string $manager,
        string $package,
        string $title,
        array $ruleIds,
        string $strategy,
        string $reason,
        array $metadata,
    ): ResolutionPlanItem {
        return new ResolutionPlanItem(
            id: 'javascript-manual-' . md5($manager . $package . implode('|', $ruleIds)),
            source: 'npm',
            package: $package,
            title: $title,
            ruleIds: $ruleIds,
            commands: [],
            expectedFiles: ['package.json'],
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
