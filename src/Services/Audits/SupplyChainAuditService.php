<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use JsonException;
use Symfony\Component\Process\Process;

class SupplyChainAuditService implements AuditServiceInterface
{
    public function getName(): string
    {
        return 'supply-chain';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        $minimumAgeDays = config('warden.audits.supply_chain.minimum_release_age_days', 3);
        if (!is_int($minimumAgeDays) || $minimumAgeDays < 0 || $minimumAgeDays > 30) {
            return AuditResult::failed($this->getName(), 'invalid_configuration', 'minimum_release_age_days must be between 0 and 30.');
        }

        $composer = $this->readJson('composer.json');
        if ($composer === null) {
            return AuditResult::failed($this->getName(), 'invalid_composer_json', 'composer.json is missing or invalid JSON.');
        }

        [$composerFindings, $composerErrors] = $this->composerValidation();
        $findings = [
            ...$composerFindings,
            ...$this->composerConfigurationFindings($composer),
            ...$this->composerReleaseFindings($auditContext),
            ...$this->javascriptLockFindings(),
        ];

        return new AuditResult($this->getName(), $findings, $composerErrors);
    }

    /** @return array{0: list<Finding>, 1: list<AuditError>} */
    private function composerValidation(): array
    {
        if (!is_file(base_path('composer.lock'))) {
            return [[new Finding(
                id: 'supply-chain.composer-lock.missing',
                source: $this->getName(),
                title: 'Composer lockfile is missing',
                severity: Severity::High,
                description: 'Dependency versions are not pinned by composer.lock.',
                remediation: 'Run composer update and commit composer.lock.',
                path: 'composer.json',
            )], []];
        }

        $process = $this->createComposerValidationProcess();
        $process->run();
        if ($process->isSuccessful()) {
            return [[], []];
        }

        $output = trim($process->getErrorOutput() . "\n" . $process->getOutput());
        if (!str_contains(strtolower($output), 'lock file')) {
            return [[], [new AuditError(
                $this->getName(),
                'composer_validation_failed',
                $output !== '' ? $output : 'Composer could not validate the dependency manifest.',
            )]];
        }

        return [[new Finding(
            id: 'supply-chain.composer-lock.stale',
            source: $this->getName(),
            title: 'Composer lockfile is not synchronized',
            severity: Severity::High,
            description: $output,
            remediation: 'Run composer update for the changed constraints and commit the refreshed lockfile.',
            path: 'composer.lock',
        )], []];
    }

    protected function createComposerValidationProcess(): Process
    {
        return new Process(
            ['composer', 'validate', '--no-check-publish', '--no-interaction'],
            base_path(),
            null,
            null,
            60,
        );
    }

    /**
     * @param array<string, mixed> $composer
     * @return list<Finding>
     */
    private function composerConfigurationFindings(array $composer): array
    {
        $findings = [];
        $config = is_array($composer['config'] ?? null) ? $composer['config'] : [];

        if (($config['secure-http'] ?? true) === false) {
            $findings[] = new Finding(
                id: 'supply-chain.composer.insecure-http',
                source: $this->getName(),
                title: 'Composer secure HTTP is disabled',
                severity: Severity::High,
                description: 'Composer is allowed to download packages over unencrypted HTTP.',
                remediation: 'Remove secure-http=false and use HTTPS repositories.',
                path: 'composer.json',
            );
        }

        $allowPlugins = $config['allow-plugins'] ?? null;
        if ($allowPlugins === true || (is_array($allowPlugins) && ($allowPlugins['*'] ?? false) === true)) {
            $findings[] = new Finding(
                id: 'supply-chain.composer.plugins.unrestricted',
                source: $this->getName(),
                title: 'Composer plugins are unrestricted',
                severity: Severity::High,
                description: 'Any dependency may execute Composer plugin code during installation.',
                remediation: 'Allow only explicitly reviewed plugin package names.',
                path: 'composer.json',
            );
        }

        $repositories = $composer['repositories'] ?? [];
        if (is_array($repositories)) {
            foreach ($repositories as $repository) {
                if (!is_array($repository)) {
                    continue;
                }

                $url = $repository['url'] ?? null;
                if (is_string($url) && str_starts_with(strtolower($url), 'http://')) {
                    $findings[] = new Finding(
                        id: 'supply-chain.composer.repository.insecure',
                        source: $this->getName(),
                        title: 'Insecure Composer repository URL',
                        severity: Severity::High,
                        description: sprintf('Composer repository %s uses unencrypted HTTP.', $url),
                        remediation: 'Use an HTTPS or authenticated SSH repository URL.',
                        reference: $url,
                        path: 'composer.json',
                    );
                }
            }
        }

        return $findings;
    }

    /** @return list<Finding> */
    private function javascriptLockFindings(): array
    {
        if (!is_file(base_path('package.json'))) {
            return [];
        }

        $supportedLock = is_file(base_path('package-lock.json'));
        $unsupported = array_values(array_filter(
            ['yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'],
            static fn (string $path): bool => is_file(base_path($path)),
        ));

        if (!$supportedLock) {
            return [new Finding(
                id: $unsupported === [] ? 'supply-chain.javascript-lock.missing' : 'supply-chain.javascript-lock.unsupported',
                source: $this->getName(),
                title: $unsupported === [] ? 'JavaScript lockfile is missing' : 'JavaScript lockfile is not yet supported',
                severity: $unsupported === [] ? Severity::High : Severity::Medium,
                description: $unsupported === []
                    ? 'JavaScript dependency versions are not pinned.'
                    : sprintf('Warden cannot audit %s yet.', implode(', ', $unsupported)),
                remediation: $unsupported === []
                    ? 'Generate and commit a package-lock.json file.'
                    : 'Run the package manager audit separately and select --skip=npm.',
                path: 'package.json',
            )];
        }

        $package = $this->readJson('package.json');
        $lock = $this->readJson('package-lock.json');
        if ($package === null || $lock === null) {
            return [new Finding(
                id: 'supply-chain.javascript-lock.invalid',
                source: $this->getName(),
                title: 'JavaScript manifest or lockfile is invalid',
                severity: Severity::High,
                description: 'package.json and package-lock.json must contain valid JSON.',
                remediation: 'Regenerate package-lock.json with npm install --package-lock-only.',
                path: 'package-lock.json',
            )];
        }

        $root = is_array($lock['packages'][''] ?? null) ? $lock['packages'][''] : [];
        foreach (['dependencies', 'devDependencies', 'optionalDependencies'] as $key) {
            $manifestDependencies = is_array($package[$key] ?? null) ? $package[$key] : [];
            $lockedDependencies = is_array($root[$key] ?? null) ? $root[$key] : [];
            if ($manifestDependencies !== $lockedDependencies) {
                return [new Finding(
                    id: 'supply-chain.javascript-lock.stale',
                    source: $this->getName(),
                    title: 'JavaScript lockfile is not synchronized',
                    severity: Severity::High,
                    description: sprintf('%s differs between package.json and package-lock.json.', $key),
                    remediation: 'Run npm install --package-lock-only and commit package-lock.json.',
                    path: 'package-lock.json',
                )];
            }
        }

        return [];
    }

    /** @return list<Finding> */
    private function composerReleaseFindings(AuditContext $auditContext): array
    {
        $minimumAgeDays = config('warden.audits.supply_chain.minimum_release_age_days', 3);
        if ($minimumAgeDays === 0) {
            return [];
        }

        $lock = $this->readJson('composer.lock');
        if ($lock === null) {
            return [];
        }

        $sections = $auditContext->scope === 'production' ? ['packages'] : ['packages', 'packages-dev'];
        $threshold = $auditContext->scanTime()->subDays($minimumAgeDays);
        $findings = [];

        foreach ($sections as $section) {
            $packages = $lock[$section] ?? [];
            if (!is_array($packages)) {
                continue;
            }

            foreach ($packages as $package) {
                if (!is_array($package) || !is_string($package['name'] ?? null)) {
                    continue;
                }

                $name = $package['name'];
                $version = is_string($package['version'] ?? null) ? $package['version'] : 'unknown';
                $releasedAt = is_string($package['time'] ?? null) ? $package['time'] : null;
                if ($releasedAt === null) {
                    $findings[] = $this->releaseTimeMissingFinding($name, $version);
                    continue;
                }

                try {
                    $release = \Carbon\CarbonImmutable::parse($releasedAt);
                } catch (\Throwable) {
                    $release = null;
                }

                if (!$release instanceof \Carbon\CarbonImmutable) {
                    $findings[] = $this->releaseTimeMissingFinding($name, $version);
                    continue;
                }

                if ($release->lessThan($threshold)) {
                    continue;
                }

                $autoload = is_array($package['autoload'] ?? null) ? $package['autoload'] : [];
                $hasAutoloadFiles = is_array($autoload['files'] ?? null) && $autoload['files'] !== [];
                $isPlugin = ($package['type'] ?? null) === 'composer-plugin';
                $executable = $hasAutoloadFiles || $isPlugin;

                $findings[] = new Finding(
                    id: $executable ? 'supply-chain.composer.recent-executable-package' : 'supply-chain.composer.recent-package',
                    source: $this->getName(),
                    title: $executable ? 'Recently released package can execute code automatically' : 'Composer package was released recently',
                    severity: $executable ? Severity::Critical : Severity::Medium,
                    description: sprintf('%s %s was released at %s%s.', $name, $version, $release->toISOString(), $executable ? ' and registers automatic execution behavior' : ''),
                    remediation: $executable
                        ? 'Verify the release provenance and source diff before allowing it into the deployment.'
                        : 'Delay deployment until the review window passes or explicitly accept the advisory.',
                    package: $name,
                    path: 'composer.lock',
                    blocking: $executable,
                    metadata: ['released_at' => $release->toISOString(), 'scope' => $section === 'packages-dev' ? 'development' : 'production'],
                    identity: $name . '@' . $version,
                );
            }
        }

        return $findings;
    }

    private function releaseTimeMissingFinding(string $name, string $version): Finding
    {
        return new Finding(
            id: 'supply-chain.composer.release-time-missing',
            source: $this->getName(),
            title: 'Composer package release time is unavailable',
            severity: Severity::Low,
            description: sprintf('%s %s cannot be evaluated by the release-age policy.', $name, $version),
            remediation: 'Review the private package provenance and provide release metadata when possible.',
            package: $name,
            path: 'composer.lock',
            blocking: false,
            identity: $name . '@' . $version,
        );
    }

    /** @return array<string, mixed>|null */
    private function readJson(string $path): ?array
    {
        $contents = @file_get_contents(base_path($path));
        if (!is_string($contents)) {
            return null;
        }

        try {
            $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }
}
