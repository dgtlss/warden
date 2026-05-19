<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;

class ComposerAuditService extends AbstractAuditService
{
    /**
     * @var array<array<string, mixed>>
     */
    private array $abandonedPackages = [];

    /**
     * @var array<string, string>
     */
    private array $directDependencies = [];

    /**
     * @var array<string, string>
     */
    private array $directDevDependencies = [];

    /**
     * @var array<string, string>
     */
    private array $lockedPackages = [];

    /**
     * @var array<string, string>
     */
    private array $lockedDevPackages = [];

    public function getName(): string
    {
        return 'composer';
    }

    public function run(): bool
    {
        $this->hydrateComposerMetadata();

        $command = ['composer', 'audit', '--format=json'];

        if (file_exists(base_path('composer.lock'))) {
            $command[] = '--locked';
        }

        if (!(bool) config('warden.policy.composer.include_dev_dependencies', true)) {
            $command[] = '--no-dev';
        }

        $process = new Process($command);
        $process->setWorkingDirectory(base_path());
        $process->setTimeout(60);
        
        try {
            $process->run();
            
            // Exit code 1 from composer audit means vulnerabilities were found, which is okay
            // Only treat it as an error if we can't parse the output as JSON
            $output = json_decode($process->getOutput(), true);
            if ($output === null) {
                $errorOutput = $process->getErrorOutput() ?: $process->getOutput() ?: 'No error output available';
                $exitCode = $process->getExitCode();
                
                $this->addFinding([
                    'source' => $this->getName(),
                    'package' => 'composer',
                    'title' => 'Composer audit failed to run',
                    'severity' => 'high',
                    'error' => "Exit Code: {$exitCode}\nError: {$errorOutput}"
                ]);
                
                return false;
            }

            // Handle abandoned packages (but don't fail the audit)
            if (isset($output['abandoned']) && !empty($output['abandoned'])) {
                foreach ($output['abandoned'] as $package => $replacement) {
                    $packageMetadata = $this->packageMetadata($package);

                    $this->abandonedPackages[] = [
                        'package' => $package,
                        'replacement' => is_string($replacement) ? $replacement : null,
                        'resolvable' => $packageMetadata['is_direct_dependency'] && is_string($replacement) && $replacement !== '',
                        'resolver_type' => 'composer',
                        'resolution_strategy' => 'abandoned-replace',
                        'requires_network' => true,
                        'verification_steps' => $this->verificationSteps(),
                        'is_direct_dependency' => $packageMetadata['is_direct_dependency'],
                        'is_dev_dependency' => $packageMetadata['is_dev_dependency'],
                        'declared_constraint' => $packageMetadata['declared_constraint'],
                        'installed_version' => $packageMetadata['installed_version'],
                    ];
                }
            }

            // Handle security advisories
            if (isset($output['advisories']) && !empty($output['advisories'])) {
                foreach ($output['advisories'] as $package => $issues) {
                    foreach ($issues as $issue) {
                        $packageMetadata = $this->packageMetadata($package);

                        $this->addFinding([
                            'source' => $this->getName(),
                            'package' => $package,
                            'title' => $issue['title'],
                            'rule_id' => isset($issue['cve']) && is_string($issue['cve']) && $issue['cve'] !== ''
                                ? $issue['cve']
                                : sprintf('composer.%s', str_replace('/', '.', $package)),
                            'category' => 'dependency',
                            'severity' => $issue['severity'] ?? 'unknown',
                            'cve' => $issue['cve'] ?? null,
                            'affected_versions' => $issue['affectedVersions'] ?? null,
                            'description' => $issue['title'],
                            'file' => file_exists(base_path('composer.lock')) ? 'composer.lock' : 'composer.json',
                            'resolvable' => true,
                            'resolver_type' => 'composer',
                            'resolver_targets' => [$package],
                            'resolution_strategy' => $packageMetadata['is_direct_dependency'] ? 'update-package' : 'update-dependency-path',
                            'candidate_constraints' => array_filter([
                                'declared' => $packageMetadata['declared_constraint'],
                                'installed' => $packageMetadata['installed_version'],
                            ]),
                            'requires_network' => true,
                            'verification_steps' => $this->verificationSteps(),
                            'package_manager' => 'composer',
                            'is_direct_dependency' => $packageMetadata['is_direct_dependency'],
                            'is_dev_dependency' => $packageMetadata['is_dev_dependency'],
                            'declared_constraint' => $packageMetadata['declared_constraint'],
                            'installed_version' => $packageMetadata['installed_version'],
                        ]);
                    }
                }
            }

            return true;
        } catch (\Exception $exception) {
            $this->addFinding([
                'source' => $this->getName(),
                'package' => 'composer',
                'title' => 'Composer audit failed with exception',
                'severity' => 'high',
                'error' => $exception->getMessage()
            ]);
            
            return false;
        }
    }

    /**
     * @return array<array<string, mixed>>
     */
    public function getAbandonedPackages(): array
    {
        return $this->abandonedPackages;
    }

    public function getMetadata(): array
    {
        return [
            'abandoned_packages' => $this->abandonedPackages,
        ];
    }

    private function hydrateComposerMetadata(): void
    {
        $composerJsonPath = base_path('composer.json');
        if (file_exists($composerJsonPath)) {
            $contents = file_get_contents($composerJsonPath);
            $decoded = $contents !== false ? json_decode($contents, true) : null;

            if (is_array($decoded)) {
                $this->directDependencies = isset($decoded['require']) && is_array($decoded['require'])
                    ? array_filter($decoded['require'], static fn ($value, $key): bool => is_string($key) && is_string($value), ARRAY_FILTER_USE_BOTH)
                    : [];
                $this->directDevDependencies = isset($decoded['require-dev']) && is_array($decoded['require-dev'])
                    ? array_filter($decoded['require-dev'], static fn ($value, $key): bool => is_string($key) && is_string($value), ARRAY_FILTER_USE_BOTH)
                    : [];
            }
        }

        $composerLockPath = base_path('composer.lock');
        if (!file_exists($composerLockPath)) {
            return;
        }

        $contents = file_get_contents($composerLockPath);
        $decoded = $contents !== false ? json_decode($contents, true) : null;

        if (!is_array($decoded)) {
            return;
        }

        foreach (($decoded['packages'] ?? []) as $package) {
            if (is_array($package) && isset($package['name'], $package['version']) && is_string($package['name']) && is_string($package['version'])) {
                $this->lockedPackages[$package['name']] = $package['version'];
            }
        }

        foreach (($decoded['packages-dev'] ?? []) as $package) {
            if (is_array($package) && isset($package['name'], $package['version']) && is_string($package['name']) && is_string($package['version'])) {
                $this->lockedDevPackages[$package['name']] = $package['version'];
            }
        }
    }

    /**
     * @return array{is_direct_dependency: bool, is_dev_dependency: bool, declared_constraint: string|null, installed_version: string|null}
     */
    private function packageMetadata(string $package): array
    {
        $declaredConstraint = $this->directDependencies[$package] ?? $this->directDevDependencies[$package] ?? null;
        $isDevDependency = array_key_exists($package, $this->directDevDependencies);

        return [
            'is_direct_dependency' => array_key_exists($package, $this->directDependencies) || $isDevDependency,
            'is_dev_dependency' => $isDevDependency,
            'declared_constraint' => $declaredConstraint,
            'installed_version' => $this->lockedPackages[$package] ?? $this->lockedDevPackages[$package] ?? null,
        ];
    }

    /**
     * @return array<int, string>
     */
    private function verificationSteps(): array
    {
        return [
            'composer phpstan',
            'vendor/bin/phpunit tests/',
            'warden:audit --no-notify',
        ];
    }
}
