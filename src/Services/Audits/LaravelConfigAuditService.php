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
            ...$this->corsFindings(),
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
        $findings = [];
        if ($this->classAvailable('Laravel\\Telescope\\Telescope') && config('telescope.enabled') === true) {
            $findings[] = new Finding(
                id: 'laravel.debug-tool.telescope-enabled',
                source: $this->getName(),
                title: 'Laravel Telescope is enabled in production',
                severity: Severity::High,
                description: 'Telescope records sensitive request, query, job, and exception data.',
                remediation: 'Disable Telescope or verify access authorization and data filtering before deployment.',
                package: 'laravel/telescope',
                path: 'config/telescope.php',
                identity: 'laravel/telescope',
            );
        }

        $tools = [
            ['Barryvdh\\Debugbar\\LaravelDebugbar', 'debugbar.enabled', 'laravel.debug-tool.debugbar-enabled', 'barryvdh/laravel-debugbar', 'Laravel Debugbar'],
            ['Clockwork\\Clockwork', 'clockwork.enable', 'laravel.debug-tool.clockwork-enabled', 'itsgoingd/clockwork', 'Clockwork'],
        ];
        foreach ($tools as [$class, $configKey, $id, $package, $label]) {
            if ($this->classAvailable($class) && config()->get($configKey) === true) {
                $findings[] = new Finding(
                    id: $id,
                    source: $this->getName(),
                    title: sprintf('%s is enabled in production', $label),
                    severity: Severity::High,
                    description: sprintf('%s may expose requests, queries, exceptions, and application internals.', $label),
                    remediation: sprintf('Disable %s in the effective production configuration.', $label),
                    package: $package,
                    path: 'config',
                    identity: $package,
                );
            }
        }

        return $findings;
    }

    /** @param class-string|string $class */
    private function classAvailable(string $class): bool
    {
        return class_exists($class);
    }

    /** @return list<Finding> */
    private function corsFindings(): array
    {
        $origins = config('cors.allowed_origins', []);
        $patterns = config('cors.allowed_origins_patterns', []);
        $credentials = config('cors.supports_credentials') === true;
        $wildcard = (is_array($origins) && in_array('*', $origins, true))
            || (is_array($patterns) && in_array('.*', $patterns, true));

        if (!$wildcard) {
            return [];
        }

        return [new Finding(
            id: $credentials ? 'laravel.cors.wildcard-credentials' : 'laravel.cors.wildcard-origin',
            source: $this->getName(),
            title: $credentials ? 'Credentialed CORS accepts every origin' : 'CORS accepts every origin',
            severity: $credentials ? Severity::High : Severity::Low,
            description: $credentials
                ? 'Wildcard origins combined with credential support can expose authenticated responses cross-origin.'
                : 'Every origin can call routes covered by the CORS configuration.',
            remediation: 'Configure an explicit list of trusted production origins.',
            path: 'config/cors.php',
            blocking: $credentials,
            identity: 'wildcard-origin',
        )];
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
