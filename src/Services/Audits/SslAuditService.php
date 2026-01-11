<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Enums\Severity;
use Illuminate\Support\Facades\Config;

class SslAuditService extends AbstractAuditService
{
    public function run(): bool
    {
        $this->checkForceHttps();
        $this->checkSessionSecure();
        $this->checkAssetUrl();

        return true;
    }

    public function getName(): string
    {
        return 'SSL/TLS Configuration';
    }

    /**
     * Check if HTTPS is enforced in production.
     */
    protected function checkForceHttps(): void
    {
        $isProduction = Config::get('app.env') === 'production';
        $appUrl = Config::get('app.url', '');
        if (!is_string($appUrl)) {
            $appUrl = '';
        }

        if ($isProduction && !str_starts_with($appUrl, 'https://')) {
            $this->addFinding([
                'package' => 'Application Configuration',
                'title' => 'HTTPS not enforced in production',
                'severity' => Severity::CRITICAL,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'APP_URL should use https:// in production. Update your .env file and consider using middleware to force HTTPS.',
            ]);
        }
    }

    /**
     * Check if session cookies are marked as secure.
     */
    protected function checkSessionSecure(): void
    {
        $isProduction = Config::get('app.env') === 'production';
        $sessionSecure = Config::get('session.secure', false);
        $sessionHttpOnly = Config::get('session.http_only', true);

        if ($isProduction && !$sessionSecure) {
            $this->addFinding([
                'package' => 'Session Configuration',
                'title' => 'Session cookies not marked as secure',
                'severity' => Severity::HIGH,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Set SESSION_SECURE_COOKIE=true in production to prevent session hijacking over insecure connections.',
            ]);
        }

        if (!$sessionHttpOnly) {
            $this->addFinding([
                'package' => 'Session Configuration',
                'title' => 'Session cookies accessible via JavaScript',
                'severity' => Severity::MEDIUM,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Session cookies should have the HttpOnly flag to prevent XSS attacks from stealing session data.',
            ]);
        }

        // Check for SameSite attribute
        $sessionSameSite = Config::get('session.same_site', 'lax');
        if (!is_string($sessionSameSite) || !in_array(strtolower($sessionSameSite), ['lax', 'strict', 'none'], true)) {
            $this->addFinding([
                'package' => 'Session Configuration',
                'title' => 'Invalid SameSite cookie attribute',
                'severity' => Severity::MEDIUM,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'SESSION_SAME_SITE should be set to "lax" or "strict" to prevent CSRF attacks.',
            ]);
        }
    }

    /**
     * Check for mixed content issues (HTTP resources on HTTPS pages).
     */
    protected function checkAssetUrl(): void
    {
        $isProduction = Config::get('app.env') === 'production';
        $appUrl = Config::get('app.url', '');
        if (!is_string($appUrl)) {
            $appUrl = '';
        }

        $assetUrl = Config::get('app.asset_url', '');
        if (!is_string($assetUrl)) {
            $assetUrl = '';
        }

        if ($isProduction && str_starts_with($appUrl, 'https://')) {
            if (!empty($assetUrl) && str_starts_with($assetUrl, 'http://')) {
                $this->addFinding([
                    'package' => 'Application Configuration',
                    'title' => 'Mixed content: HTTP assets on HTTPS site',
                    'severity' => Severity::HIGH,
                    'cve' => null,
                    'affected_versions' => null,
                    'error' => 'ASSET_URL uses http:// while APP_URL uses https://, causing mixed content warnings and security issues.',
                ]);
            }
        }
    }
}
