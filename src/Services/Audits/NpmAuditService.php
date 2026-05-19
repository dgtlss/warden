<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;

class NpmAuditService extends AbstractAuditService
{
    /**
     * @var array<int, string>
     */
    private array $lockfiles = [
        'package-lock.json',
        'pnpm-lock.yaml',
        'yarn.lock',
    ];

    /**
     * @var array<string, string>
     */
    private array $dependencies = [];

    /**
     * @var array<string, string>
     */
    private array $devDependencies = [];

    public function getName(): string
    {
        return 'npm';
    }

    public function run(): bool
    {
        $this->hydratePackageMetadata();

        if (!file_exists(base_path('package.json'))) {
            $this->addFinding([
                'package' => 'npm',
                'title' => 'Missing package.json',
                'rule_id' => 'javascript.package-json.missing',
                'category' => 'dependency',
                'severity' => 'error',
                'cve' => null,
                'affected_versions' => null,
                'description' => 'JavaScript dependency auditing was requested, but no package.json file exists.',
                'file' => 'package.json',
            ]);
            return false;
        }

        $lockfile = $this->detectLockfile();

        if ($lockfile === null) {
            $this->addFinding([
                'package' => 'npm',
                'title' => 'Missing supported JavaScript lockfile',
                'rule_id' => 'javascript.lockfile.missing',
                'category' => 'dependency',
                'severity' => 'error',
                'cve' => null,
                'affected_versions' => null,
                'description' => 'Warden expected package-lock.json, pnpm-lock.yaml, or yarn.lock in order to audit JavaScript dependencies.',
                'file' => 'package.json',
            ]);
            return false;
        }

        $process = new Process($this->commandForLockfile($lockfile));
        $process->setWorkingDirectory(base_path());
        $process->setTimeout(config('warden.audits.timeout', 300));

        $packageManager = $this->packageManagerForLockfile($lockfile);

        try {
            $process->run();
            
            // npm audit returns non-zero exit codes when vulnerabilities are found, which is normal
            // Only treat it as an error if we can't parse the JSON output
            $output = json_decode($process->getOutput(), true);
            if ($output === null) {
                $errorOutput = $process->getErrorOutput() ?: $process->getOutput() ?: 'No error output available';
                $exitCode = $process->getExitCode();
                
                $this->addFinding([
                    'package' => 'npm',
                    'title' => 'npm audit failed to run',
                    'rule_id' => 'javascript.audit.execution-failed',
                    'category' => 'dependency',
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null,
                    'description' => 'The JavaScript dependency audit command failed to produce valid JSON output.',
                    'file' => $lockfile,
                    'error' => "Exit Code: {$exitCode}\nError: {$errorOutput}"
                ]);
                return false;
            }

            // Handle modern npm audit format (npm 7+)
            if (isset($output['vulnerabilities'])) {
                foreach ($output['vulnerabilities'] as $package => $vulnerability) {
                    // Modern format has vulnerability details in the 'via' array
                    if (isset($vulnerability['via']) && is_array($vulnerability['via'])) {
                        foreach ($vulnerability['via'] as $viaItem) {
                            // Skip string entries (they're just package names), process array entries
                            if (is_array($viaItem)) {
                                $packageMetadata = $this->packageMetadata($package);
                                $this->addFinding([
                                    'package' => $package,
                                    'title' => $viaItem['title'] ?? 'Unknown vulnerability',
                                    'rule_id' => $this->ruleIdForPackage($package, $viaItem['title'] ?? 'unknown'),
                                    'category' => 'dependency',
                                    'severity' => $viaItem['severity'] ?? 'unknown',
                                    'cve' => $viaItem['url'] ?? null,
                                    'affected_versions' => $viaItem['range'] ?? ($vulnerability['range'] ?? 'unknown'),
                                    'description' => $viaItem['title'] ?? 'Unknown vulnerability',
                                    'file' => $lockfile,
                                    'resolvable' => true,
                                    'resolver_type' => 'javascript',
                                    'resolver_targets' => [$package],
                                    'resolution_strategy' => $packageMetadata['is_direct_dependency'] ? 'update-package' : 'audit-fix',
                                    'candidate_constraints' => array_filter([
                                        'declared' => $packageMetadata['declared_constraint'],
                                    ]),
                                    'requires_network' => true,
                                    'verification_steps' => $this->verificationSteps(),
                                    'package_manager' => $packageManager,
                                    'lockfile' => $lockfile,
                                    'is_direct_dependency' => $packageMetadata['is_direct_dependency'],
                                    'is_dev_dependency' => $packageMetadata['is_dev_dependency'],
                                    'declared_constraint' => $packageMetadata['declared_constraint'],
                                ]);
                            }
                        }
                    } else {
                        $packageMetadata = $this->packageMetadata($package);
                        // Fallback for potential legacy format or missing via array
                        $this->addFinding([
                            'package' => $package,
                            'title' => $vulnerability['title'] ?? 'Unknown vulnerability',
                            'rule_id' => $this->ruleIdForPackage($package, $vulnerability['title'] ?? 'unknown'),
                            'category' => 'dependency',
                            'severity' => $vulnerability['severity'] ?? 'unknown',
                            'cve' => $vulnerability['url'] ?? null,
                            'affected_versions' => $vulnerability['range'] ?? 'unknown',
                            'description' => $vulnerability['title'] ?? 'Unknown vulnerability',
                            'file' => $lockfile,
                            'resolvable' => true,
                            'resolver_type' => 'javascript',
                            'resolver_targets' => [$package],
                            'resolution_strategy' => $packageMetadata['is_direct_dependency'] ? 'update-package' : 'audit-fix',
                            'candidate_constraints' => array_filter([
                                'declared' => $packageMetadata['declared_constraint'],
                            ]),
                            'requires_network' => true,
                            'verification_steps' => $this->verificationSteps(),
                            'package_manager' => $packageManager,
                            'lockfile' => $lockfile,
                            'is_direct_dependency' => $packageMetadata['is_direct_dependency'],
                            'is_dev_dependency' => $packageMetadata['is_dev_dependency'],
                            'declared_constraint' => $packageMetadata['declared_constraint'],
                        ]);
                    }
                }
            }
            
            // Handle legacy npm audit format (npm v6 and earlier) - advisories format
            if (isset($output['advisories'])) {
                foreach ($output['advisories'] as $advisory) {
                    $packageName = $advisory['module_name'] ?? 'unknown';
                    $packageMetadata = $this->packageMetadata($packageName);
                    $this->addFinding([
                        'package' => $packageName,
                        'title' => $advisory['title'] ?? 'Unknown vulnerability',
                        'rule_id' => $this->ruleIdForPackage($packageName, $advisory['title'] ?? 'unknown'),
                        'category' => 'dependency',
                        'severity' => $advisory['severity'] ?? 'unknown',
                        'cve' => $advisory['cves'][0] ?? $advisory['url'] ?? null,
                        'affected_versions' => $advisory['vulnerable_versions'] ?? 'unknown',
                        'description' => $advisory['title'] ?? 'Unknown vulnerability',
                        'file' => $lockfile,
                        'resolvable' => true,
                        'resolver_type' => 'javascript',
                        'resolver_targets' => [$packageName],
                        'resolution_strategy' => $packageMetadata['is_direct_dependency'] ? 'update-package' : 'audit-fix',
                        'candidate_constraints' => array_filter([
                            'declared' => $packageMetadata['declared_constraint'],
                        ]),
                        'requires_network' => true,
                        'verification_steps' => $this->verificationSteps(),
                        'package_manager' => $packageManager,
                        'lockfile' => $lockfile,
                        'is_direct_dependency' => $packageMetadata['is_direct_dependency'],
                        'is_dev_dependency' => $packageMetadata['is_dev_dependency'],
                        'declared_constraint' => $packageMetadata['declared_constraint'],
                    ]);
                }
            }

            return true;
        } catch (\Exception $exception) {
            $this->addFinding([
                'package' => 'npm',
                'title' => 'npm audit failed with exception',
                'rule_id' => 'javascript.audit.exception',
                'category' => 'dependency',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null,
                'description' => 'The JavaScript dependency audit command raised an exception before it could complete.',
                'error' => $exception->getMessage()
            ]);
            return false;
        }
    }

    private function detectLockfile(): ?string
    {
        foreach ($this->lockfiles as $lockfile) {
            if (file_exists(base_path($lockfile))) {
                return $lockfile;
            }
        }

        return null;
    }

    /**
     * @return array<int, string>
     */
    private function commandForLockfile(string $lockfile): array
    {
        return match ($lockfile) {
            'pnpm-lock.yaml' => ['pnpm', 'audit', '--json'],
            'yarn.lock' => ['yarn', 'npm', 'audit', '--json'],
            default => ['npm', 'audit', '--json'],
        };
    }

    private function packageManagerForLockfile(string $lockfile): string
    {
        return match ($lockfile) {
            'pnpm-lock.yaml' => 'pnpm',
            'yarn.lock' => 'yarn',
            default => 'npm',
        };
    }

    private function ruleIdForPackage(string $package, string $title): string
    {
        return sprintf(
            'javascript.%s.%s',
            str_replace('/', '.', $package),
            trim((string) preg_replace('/[^a-zA-Z0-9]+/', '-', strtolower($title)), '-')
        );
    }

    private function hydratePackageMetadata(): void
    {
        $packageJsonPath = base_path('package.json');
        if (!file_exists($packageJsonPath)) {
            return;
        }

        $contents = file_get_contents($packageJsonPath);
        if ($contents === false) {
            return;
        }

        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            return;
        }

        $this->dependencies = isset($decoded['dependencies']) && is_array($decoded['dependencies'])
            ? array_filter($decoded['dependencies'], static fn ($value, $key): bool => is_string($key) && is_string($value), ARRAY_FILTER_USE_BOTH)
            : [];
        $this->devDependencies = isset($decoded['devDependencies']) && is_array($decoded['devDependencies'])
            ? array_filter($decoded['devDependencies'], static fn ($value, $key): bool => is_string($key) && is_string($value), ARRAY_FILTER_USE_BOTH)
            : [];
    }

    /**
     * @return array{is_direct_dependency: bool, is_dev_dependency: bool, declared_constraint: string|null}
     */
    private function packageMetadata(string $package): array
    {
        $declaredConstraint = $this->dependencies[$package] ?? $this->devDependencies[$package] ?? null;
        $isDevDependency = array_key_exists($package, $this->devDependencies);

        return [
            'is_direct_dependency' => array_key_exists($package, $this->dependencies) || $isDevDependency,
            'is_dev_dependency' => $isDevDependency,
            'declared_constraint' => $declaredConstraint,
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
