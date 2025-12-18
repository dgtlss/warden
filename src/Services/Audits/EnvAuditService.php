<?php

namespace Dgtlss\Warden\Services\Audits;

class EnvAuditService extends AbstractAuditService
{
    private array $sensitiveKeys;

    public function __construct()
    {
        $this->sensitiveKeys = config('warden.sensitive_keys');
    }

    public function getName(): string
    {
        return 'environment';
    }

    public function run(): bool
    {
        // Check if .env exists
        if (!file_exists(base_path('.env'))) {
            $this->addFinding([
                'package' => 'environment',
                'title' => 'Missing .env file',
                'severity' => 'critical',
                'cve' => null,
                'affected_versions' => null
            ]);
            return false;
        }

        // Check if .env is in .gitignore
        if (!$this->isEnvIgnored()) {
            $this->addFinding([
                'package' => 'environment',
                'title' => '.env file not listed in .gitignore',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null
            ]);
        }

        // Check for missing sensitive variables
        foreach ($this->sensitiveKeys as $sensitiveKey) {
            /** @phpstan-ignore-next-line Calling env is intentional inside audit */
            if (empty(env($sensitiveKey))) {
                $this->addFinding([
                    'package' => 'environment',
                    'title' => 'Missing sensitive environment variable: ' . $sensitiveKey,
                    'severity' => 'medium',
                    'cve' => null,
                    'affected_versions' => null
                ]);
            }
        }

        return true;
    }

    private function isEnvIgnored(): bool
    {
        $gitignorePath = base_path('.gitignore');
        if (!file_exists($gitignorePath)) {
            return false;
        }
        
        $gitignore = file_get_contents($gitignorePath);
        return strpos((string) $gitignore, '.env') !== false;
    }
}
