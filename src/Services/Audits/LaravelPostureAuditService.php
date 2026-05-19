<?php

namespace Dgtlss\Warden\Services\Audits;

class LaravelPostureAuditService extends AbstractAuditService
{
    public function getName(): string
    {
        return 'laravel-posture';
    }

    public function run(): bool
    {
        $this->checkAppKey();
        $this->checkSessionSecurity();
        $this->checkCorsConfiguration();
        $this->checkPublicStorageExposure();

        return true;
    }

    private function checkAppKey(): void
    {
        if (!empty(config('app.key'))) {
            return;
        }

        $this->addFinding([
            'package' => 'laravel',
            'title' => 'APP_KEY is missing',
            'rule_id' => 'laravel.app-key.missing',
            'category' => 'laravel',
            'severity' => 'high',
            'description' => 'Laravel requires APP_KEY for encryption, signed URLs, and cookie security.',
            'file' => '.env',
            'remediation' => 'Generate and configure a valid APP_KEY before deploying or promoting the application.',
        ]);
    }

    private function checkSessionSecurity(): void
    {
        if (config('session.http_only') !== true) {
            $this->addFinding([
                'package' => 'laravel',
                'title' => 'Session cookies are not HTTP only',
                'rule_id' => 'laravel.session.http-only.disabled',
                'category' => 'laravel',
                'severity' => 'medium',
                'description' => 'Session cookies should be marked HTTP only so browsers do not expose them to JavaScript.',
                'file' => 'config/session.php',
                'remediation' => 'Set session.http_only to true for production-facing applications.',
            ]);
        }

        if (config('app.env') === 'production' && config('session.secure') !== true) {
            $this->addFinding([
                'package' => 'laravel',
                'title' => 'Session cookies are not marked secure in production',
                'rule_id' => 'laravel.session.secure.disabled',
                'category' => 'laravel',
                'severity' => 'high',
                'description' => 'Production cookies should be transmitted only over HTTPS.',
                'file' => 'config/session.php',
                'remediation' => 'Set session.secure to true when the application is served over HTTPS.',
            ]);
        }

        if (config('session.same_site') === 'none' && config('session.secure') !== true) {
            $this->addFinding([
                'package' => 'laravel',
                'title' => 'SameSite=None cookies are not secure',
                'rule_id' => 'laravel.session.samesite-none-insecure',
                'category' => 'laravel',
                'severity' => 'medium',
                'description' => 'Browsers require SameSite=None cookies to also be Secure, otherwise behavior is inconsistent and risky.',
                'file' => 'config/session.php',
                'remediation' => 'Pair SameSite=None with secure cookies, or use a stricter SameSite policy.',
            ]);
        }
    }

    private function checkCorsConfiguration(): void
    {
        $allowedOrigins = config('cors.allowed_origins', []);
        $supportsCredentials = (bool) config('cors.supports_credentials', false);

        if (!is_array($allowedOrigins)) {
            return;
        }

        if (in_array('*', $allowedOrigins, true) && $supportsCredentials) {
            $this->addFinding([
                'package' => 'laravel',
                'title' => 'CORS allows any origin while supporting credentials',
                'rule_id' => 'laravel.cors.wildcard-credentials',
                'category' => 'laravel',
                'severity' => 'high',
                'description' => 'Wildcard origins combined with credentialed requests creates an unsafe cross-origin posture.',
                'file' => 'config/cors.php',
                'remediation' => 'Replace wildcard origins with an explicit allow-list when credentials are enabled.',
            ]);
        }
    }

    private function checkPublicStorageExposure(): void
    {
        $publicStorage = public_path('storage');

        if (!is_dir($publicStorage)) {
            return;
        }

        if (is_link($publicStorage)) {
            return;
        }

        $this->addFinding([
            'package' => 'laravel',
            'title' => 'public/storage exists as a real directory instead of a symlink',
            'rule_id' => 'laravel.storage.public-directory',
            'category' => 'laravel',
            'severity' => 'low',
            'description' => 'A real public/storage directory can drift from Laravel storage expectations and accidentally expose files.',
            'file' => 'public/storage',
            'remediation' => 'Use the standard Laravel storage:link symlink and avoid placing sensitive data beneath public/storage.',
        ]);
    }
}
