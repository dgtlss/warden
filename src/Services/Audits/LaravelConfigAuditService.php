<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Encryption\Encrypter;
use Symfony\Component\Process\Process;
use Throwable;

class LaravelConfigAuditService implements AuditServiceInterface
{
    public function getName(): string
    {
        return 'laravel-config';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        $findings = $this->trackedEnvironmentFindings();
        if ($auditContext->profile !== 'production') {
            return AuditResult::complete($this->getName(), $findings);
        }

        return AuditResult::complete($this->getName(), [
            ...$findings,
            ...$this->applicationFindings(),
            ...$this->sessionFindings(),
            ...$this->toolingFindings(),
        ]);
    }

    /** @return list<Finding> */
    private function trackedEnvironmentFindings(): array
    {
        if (!is_file(base_path('.env'))) {
            return [];
        }

        $process = new Process(['git', 'ls-files', '--error-unmatch', '.env'], base_path());
        $process->run();
        if (!$process->isSuccessful()) {
            return [];
        }

        return [new Finding(
            id: 'laravel.env.tracked',
            source: $this->getName(),
            title: 'Environment file is tracked by Git',
            severity: Severity::Critical,
            description: '.env is present in the Git index and may expose application secrets.',
            remediation: 'Remove .env from Git history and rotate every exposed secret.',
            path: '.env',
        )];
    }

    /** @return list<Finding> */
    private function applicationFindings(): array
    {
        $findings = [];
        if (config('app.debug') === true) {
            $findings[] = $this->finding(
                'laravel.debug.enabled',
                'Debug mode is enabled in production',
                Severity::Critical,
                'Detailed exception output can disclose secrets, source paths, and configuration.',
                'Set APP_DEBUG=false in the production configuration.',
                'config/app.php',
            );
        }

        $cipher = config('app.cipher', 'AES-256-CBC');
        $key = config('app.key');
        if (!is_string($key) || !$this->validEncryptionKey($key, is_string($cipher) ? $cipher : '')) {
            $findings[] = $this->finding(
                'laravel.app-key.invalid',
                'Application encryption key is missing or invalid',
                Severity::Critical,
                'Laravel cannot safely encrypt cookies and application data with the configured key and cipher.',
                'Generate a correctly sized APP_KEY and inject it through the deployment secret store.',
                'config/app.php',
            );
        }

        $url = config('app.url');
        if (!is_string($url) || !str_starts_with(strtolower($url), 'https://')) {
            $findings[] = $this->finding(
                'laravel.url.insecure',
                'Production application URL is not HTTPS',
                Severity::High,
                'Generated absolute URLs may use an insecure HTTP origin.',
                'Set APP_URL to the public HTTPS origin.',
                'config/app.php',
            );
        }

        return $findings;
    }

    /** @return list<Finding> */
    private function sessionFindings(): array
    {
        $checks = [
            ['session.secure', true, 'laravel.session.secure', 'Session cookies are not restricted to HTTPS', Severity::High],
            ['session.http_only', true, 'laravel.session.http-only', 'Session cookies are accessible to JavaScript', Severity::High],
        ];
        $findings = [];

        foreach ($checks as [$key, $expected, $id, $title, $severity]) {
            if (config($key) !== $expected) {
                $findings[] = $this->finding(
                    $id,
                    $title,
                    $severity,
                    sprintf('%s should be enabled for production sessions.', $key),
                    sprintf('Set %s to true in the effective production configuration.', $key),
                    'config/session.php',
                );
            }
        }

        $sameSite = strtolower((string) config('session.same_site', ''));
        if (!in_array($sameSite, ['lax', 'strict', 'none'], true)) {
            $findings[] = $this->finding(
                'laravel.session.same-site',
                'Session cookie SameSite policy is weak',
                Severity::Medium,
                'The production session cookie is not configured with Lax or Strict SameSite protection.',
                'Set session.same_site to lax, strict, or an explicitly reviewed none policy.',
                'config/session.php',
            );
        }

        return $findings;
    }

    /** @return list<Finding> */
    private function toolingFindings(): array
    {
        if (class_exists(\Laravel\Telescope\Telescope::class) && config('telescope.enabled') === true) {
            return [new Finding(
                id: 'laravel.telescope.enabled',
                source: $this->getName(),
                title: 'Laravel Telescope is enabled in production',
                severity: Severity::High,
                description: 'Telescope records sensitive request, query, job, and exception data.',
                remediation: 'Disable Telescope or verify access authorization and data filtering before deployment.',
                package: 'laravel/telescope',
                path: 'config/telescope.php',
            )];
        }

        return [];
    }

    private function validEncryptionKey(string $key, string $cipher): bool
    {
        try {
            $decoded = str_starts_with($key, 'base64:') ? base64_decode(substr($key, 7), true) : $key;

            return is_string($decoded) && Encrypter::supported($decoded, $cipher);
        } catch (Throwable) {
            return false;
        }
    }

    private function finding(
        string $id,
        string $title,
        Severity $severity,
        string $description,
        string $remediation,
        string $path,
    ): Finding {
        return new Finding($id, $this->getName(), $title, $severity, $description, $remediation, path: $path);
    }
}
