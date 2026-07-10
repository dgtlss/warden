<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Audits;

use Carbon\CarbonImmutable;
use Composer\InstalledVersions;
use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use JsonException;

class PlatformAuditService implements AuditServiceInterface
{
    /** @var array<int|string, array{active: string, security: string}> */
    private const PHP_SUPPORT = [
        '8.3' => ['active' => '2025-12-31', 'security' => '2027-12-31'],
        '8.4' => ['active' => '2026-12-31', 'security' => '2028-12-31'],
        '8.5' => ['active' => '2027-12-31', 'security' => '2029-12-31'],
    ];

    /** @var array<int|string, array{active: string, security: string}> */
    private const LARAVEL_SUPPORT = [
        '12' => ['active' => '2026-08-13', 'security' => '2027-02-24'],
        '13' => ['active' => '2027-09-30', 'security' => '2028-03-17'],
    ];

    public function getName(): string
    {
        return 'platform';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        $warningDays = config('warden.audits.platform.warning_days', 90);
        if (!is_int($warningDays) || $warningDays < 0 || $warningDays > 365) {
            return AuditResult::failed($this->getName(), 'invalid_configuration', 'Platform warning_days must be between 0 and 365.');
        }

        $phpVersions = [$this->phpVersion()];
        $platform = $this->composerPlatformPhp();
        if ($platform !== null) {
            $phpVersions[] = $platform;
        }

        $findings = [];
        foreach (array_unique($phpVersions) as $version) {
            array_push($findings, ...$this->supportFindings('php', $version, self::PHP_SUPPORT, $auditContext->scanTime(), $warningDays));
        }

        $laravel = $this->laravelVersion();
        if ($laravel !== null) {
            array_push($findings, ...$this->supportFindings('laravel', $laravel, self::LARAVEL_SUPPORT, $auditContext->scanTime(), $warningDays));
        }

        return AuditResult::complete($this->getName(), $findings);
    }

    protected function phpVersion(): string
    {
        return PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '.' . PHP_RELEASE_VERSION;
    }

    protected function laravelVersion(): ?string
    {
        return InstalledVersions::isInstalled('laravel/framework') ? InstalledVersions::getPrettyVersion('laravel/framework') : null;
    }

    /**
     * @param array<int|string, array{active: string, security: string}> $calendar
     * @return list<Finding>
     */
    private function supportFindings(string $platform, string $version, array $calendar, CarbonImmutable $now, int $warningDays): array
    {
        $majorMinor = $platform === 'laravel'
            ? (string) ((int) ltrim($version, 'v'))
            : implode('.', array_slice(explode('.', ltrim($version, 'v')), 0, 2));
        $support = $calendar[$majorMinor] ?? null;
        $label = ucfirst($platform);

        if ($support === null || $now->startOfDay()->greaterThan(CarbonImmutable::parse($support['security'])->endOfDay())) {
            return [new Finding(
                id: sprintf('platform.%s.eol', $platform),
                source: $this->getName(),
                title: sprintf('%s %s is end of life', $label, $version),
                severity: Severity::Critical,
                description: sprintf('%s %s no longer receives upstream security fixes.', $label, $version),
                remediation: sprintf('Upgrade to a security-supported %s release.', $platform),
                identity: $majorMinor,
            )];
        }

        $activeUntil = CarbonImmutable::parse($support['active'])->endOfDay();
        $securityUntil = CarbonImmutable::parse($support['security'])->endOfDay();
        if ($now->greaterThan($activeUntil) || $now->diffInDays($securityUntil, false) <= $warningDays) {
            return [new Finding(
                id: sprintf('platform.%s.security-only', $platform),
                source: $this->getName(),
                title: sprintf('%s %s is in security-only or near-EOL support', $label, $version),
                severity: Severity::Low,
                description: sprintf('Upstream security support ends on %s.', $securityUntil->format('Y-m-d')),
                remediation: sprintf('Plan an upgrade before %s.', $securityUntil->format('Y-m-d')),
                blocking: false,
                identity: $majorMinor,
            )];
        }

        return [];
    }

    private function composerPlatformPhp(): ?string
    {
        $contents = @file_get_contents(base_path('composer.json'));
        if (!is_string($contents)) {
            return null;
        }

        try {
            $composer = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        $version = is_array($composer) ? ($composer['config']['platform']['php'] ?? null) : null;

        return is_string($version) && preg_match('/^\d+\.\d+(?:\.\d+)?$/', $version) === 1 ? $version : null;
    }
}
