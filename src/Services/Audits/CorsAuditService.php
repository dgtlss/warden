<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Enums\Severity;
use Illuminate\Support\Facades\Config;

class CorsAuditService extends AbstractAuditService
{
    public function run(): bool
    {
        $this->checkWildcardOrigins();
        $this->checkCredentialsWithWildcard();
        $this->checkPermissiveMethods();
        $this->checkPermissiveHeaders();

        return true;
    }

    public function getName(): string
    {
        return 'CORS Configuration';
    }

    /**
     * Check for wildcard origins in production.
     */
    protected function checkWildcardOrigins(): void
    {
        $allowedOrigins = Config::get('cors.allowed_origins', []);
        if (!is_array($allowedOrigins)) {
            $allowedOrigins = [];
        }

        $isProduction = Config::get('app.env') === 'production';

        if ($isProduction && in_array('*', $allowedOrigins, true)) {
            $this->addFinding([
                'package' => 'CORS Configuration',
                'title' => 'Wildcard CORS origin in production',
                'severity' => Severity::HIGH,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Production applications should not use wildcard (*) for allowed origins. Specify explicit domains.',
            ]);
        }
    }

    /**
     * Check for credentials allowed with wildcard origins.
     */
    protected function checkCredentialsWithWildcard(): void
    {
        $allowedOrigins = Config::get('cors.allowed_origins', []);
        if (!is_array($allowedOrigins)) {
            $allowedOrigins = [];
        }

        $supportsCredentials = Config::get('cors.supports_credentials', false);

        if ($supportsCredentials && in_array('*', $allowedOrigins, true)) {
            $this->addFinding([
                'package' => 'CORS Configuration',
                'title' => 'Credentials enabled with wildcard origin',
                'severity' => Severity::CRITICAL,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Cannot use credentials (cookies, authorization headers) with wildcard origins. This is a security violation.',
            ]);
        }
    }

    /**
     * Check for overly permissive HTTP methods.
     */
    protected function checkPermissiveMethods(): void
    {
        $allowedMethods = Config::get('cors.allowed_methods', []);
        if (!is_array($allowedMethods)) {
            $allowedMethods = [];
        }

        if (in_array('*', $allowedMethods, true)) {
            $this->addFinding([
                'package' => 'CORS Configuration',
                'title' => 'All HTTP methods allowed in CORS',
                'severity' => Severity::MEDIUM,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Allowing all HTTP methods (* wildcard) may expose dangerous operations. Specify only required methods (GET, POST, etc.).',
            ]);
        }

        // Check for potentially dangerous methods
        $dangerousMethods = ['TRACE', 'CONNECT'];
        $enabledDangerousMethods = array_intersect($allowedMethods, $dangerousMethods);

        if (!empty($enabledDangerousMethods)) {
            $this->addFinding([
                'package' => 'CORS Configuration',
                'title' => 'Dangerous HTTP methods enabled: ' . implode(', ', $enabledDangerousMethods),
                'severity' => Severity::MEDIUM,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'TRACE and CONNECT methods can be exploited for cross-site tracing attacks.',
            ]);
        }
    }

    /**
     * Check for overly permissive headers.
     */
    protected function checkPermissiveHeaders(): void
    {
        $allowedHeaders = Config::get('cors.allowed_headers', []);
        if (!is_array($allowedHeaders)) {
            $allowedHeaders = [];
        }

        if (in_array('*', $allowedHeaders, true)) {
            $this->addFinding([
                'package' => 'CORS Configuration',
                'title' => 'All headers allowed in CORS',
                'severity' => Severity::LOW,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Allowing all headers (* wildcard) may be overly permissive. Consider specifying only required headers.',
            ]);
        }
    }
}
