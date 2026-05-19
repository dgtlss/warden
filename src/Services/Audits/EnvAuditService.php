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
                'rule_id' => 'env.file.missing',
                'category' => 'configuration',
                'severity' => 'critical',
                'cve' => null,
                'affected_versions' => null,
                'description' => 'The application is missing its .env file, which usually indicates broken runtime configuration.',
                'file' => '.env',
            ]);
            return false;
        }

        // Check if .env is in .gitignore
        if (!$this->isEnvIgnored()) {
            $this->addFinding([
                'package' => 'environment',
                'title' => '.env file not listed in .gitignore',
                'rule_id' => 'env.file.not-ignored',
                'category' => 'secrets',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null,
                'description' => 'The .env file should be excluded from version control to prevent accidental secret commits.',
                'file' => '.gitignore',
            ]);
        }

        // Check for missing sensitive variables
        foreach ($this->sensitiveKeys as $sensitiveKey) {
            /** @phpstan-ignore-next-line Calling env is intentional inside audit */
            if (empty(env($sensitiveKey))) {
                $this->addFinding([
                    'package' => 'environment',
                    'title' => 'Missing sensitive environment variable: ' . $sensitiveKey,
                    'rule_id' => sprintf('env.sensitive-key.%s.missing', strtolower($sensitiveKey)),
                    'category' => 'configuration',
                    'severity' => 'medium',
                    'cve' => null,
                    'affected_versions' => null,
                    'description' => sprintf('The sensitive environment variable [%s] is missing or empty.', $sensitiveKey),
                    'file' => '.env',
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
