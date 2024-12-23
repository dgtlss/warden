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
        if (!in_array('web', config('app.middleware_groups.web', []))) {
            $this->addFinding([
                'package' => 'config',
                'title' => 'CSRF middleware may be missing',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null
            ]);
        }

        return true;
    }
}