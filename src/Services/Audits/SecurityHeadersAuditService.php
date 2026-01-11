<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Enums\Severity;
use Illuminate\Support\Facades\Config;

class SecurityHeadersAuditService extends AbstractAuditService
{
    /**
     * Required security headers and their expected configurations.
     *
     * @var array<string, array<string, mixed>>
     */
    protected array $requiredHeaders = [
        'X-Frame-Options' => [
            'expected' => ['DENY', 'SAMEORIGIN'],
            'severity' => Severity::HIGH,
            'description' => 'Prevents clickjacking attacks by controlling iframe embedding',
        ],
        'X-Content-Type-Options' => [
            'expected' => ['nosniff'],
            'severity' => Severity::MEDIUM,
            'description' => 'Prevents MIME-type sniffing vulnerabilities',
        ],
        'Strict-Transport-Security' => [
            'expected' => null, // Any value is acceptable
            'severity' => Severity::HIGH,
            'description' => 'Enforces HTTPS connections',
            'production_only' => true,
        ],
        'Content-Security-Policy' => [
            'expected' => null,
            'severity' => Severity::MEDIUM,
            'description' => 'Mitigates XSS and data injection attacks',
        ],
        'Referrer-Policy' => [
            'expected' => ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 'strict-origin-when-cross-origin'],
            'severity' => Severity::LOW,
            'description' => 'Controls referrer information sent with requests',
        ],
        'Permissions-Policy' => [
            'expected' => null,
            'severity' => Severity::LOW,
            'description' => 'Controls browser features and APIs',
        ],
    ];

    public function run(): bool
    {
        $middlewareConfig = Config::get('app.middleware');
        if (!is_array($middlewareConfig)) {
            $middlewareConfig = [];
        }

        $isProduction = Config::get('app.env') === 'production';

        foreach ($this->requiredHeaders as $header => $config) {
            // Skip production-only headers in non-production environments
            if (($config['production_only'] ?? false) && !$isProduction) {
                continue;
            }

            if (!$this->isHeaderConfigured($header, $middlewareConfig)) {
                $severity = $config['severity'];
                $description = $config['description'];

                if (!$severity instanceof Severity || !is_string($description)) {
                    continue;
                }

                $this->addFinding([
                    'package' => 'Laravel Application',
                    'title' => "Missing security header: {$header}",
                    'severity' => $severity,
                    'cve' => null,
                    'affected_versions' => null,
                    'error' => "{$description}. Consider adding this header to your middleware configuration.",
                ]);
            }
        }

        return true;
    }

    public function getName(): string
    {
        return 'Security Headers';
    }

    /**
     * Check if a security header is configured in the application.
     *
     * @param string $header
     * @param array<int|string, mixed> $middlewareConfig
     */
    protected function isHeaderConfigured(string $header, array $middlewareConfig): bool
    {
        // Check if security headers middleware is configured
        $securityHeadersMiddleware = [
            'Illuminate\Http\Middleware\HandleCors',
            'Illuminate\Http\Middleware\FrameGuard',
            'Illuminate\Http\Middleware\SetCacheHeaders',
        ];

        foreach ($securityHeadersMiddleware as $middleware) {
            if (in_array($middleware, $middlewareConfig, true)) {
                return true;
            }
        }

        // Check for custom header configuration in config files
        $customHeaders = Config::get('secure-headers.headers');
        if (is_array($customHeaders) && isset($customHeaders[$header])) {
            return true;
        }

        // Check for common security header packages
        if (class_exists('Bepsvpt\SecureHeaders\SecureHeadersMiddleware')) {
            return true;
        }

        return false;
    }
}
