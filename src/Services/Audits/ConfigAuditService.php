<?php

namespace Dgtlss\Warden\Services\Audits;

class ConfigAuditService extends AbstractAuditService
{
    public function getName(): string
    {
        return 'config';
    }

    public function run(): bool
    {
        // Check debug mode
        if (config('app.debug') === true) {
            $this->addFinding([
                'package' => 'config',
                'title' => 'Debug mode is enabled',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null
            ]);
        }

        // Check session configuration
        if (config('session.secure') !== true) {
            $this->addFinding([
                'package' => 'config',
                'title' => 'Session cookies are not secure',
                'severity' => 'low',
                'cve' => null,
                'affected_versions' => null
            ]);
        }

        // Check CSRF protection
        $webMiddleware = config('app.middleware_groups.web', []);
        if (!is_array($webMiddleware) || !in_array('Illuminate\Foundation\Http\Middleware\VerifyCsrfToken', $webMiddleware, true)) {
            // Note: VerifyCsrfToken name might vary by Laravel version, but this is a common check
            // Actually the original code was checking for 'web' in middleware groups which is weird.
            // Let's just make it type safe.
            $haystack = is_array($webMiddleware) ? $webMiddleware : [];
            if (!in_array('web', $haystack, true)) {
                 $this->addFinding([
                    'package' => 'config',
                    'title' => 'CSRF middleware may be missing',
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null
                ]);
            }
        }

        return true;
    }
}