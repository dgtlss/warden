<?php

namespace Dgtlss\Warden\Services\Audits;

class EnvAuditService extends AbstractAuditService
{
    private array $sensitiveKeys;

    public function __construct()
    {
        // Use environment variable or default sensitive keys
        $customKeys = env('WARDEN_ENV_SENSITIVE_KEYS');
        if ($customKeys) {
            $this->sensitiveKeys = explode(',', $customKeys);
        } else {
            $this->sensitiveKeys = $this->getDefaultSensitiveKeys();
        }
    }

    /**
     * Get default sensitive environment keys to check.
     */
    private function getDefaultSensitiveKeys(): array
    {
        return [
            'DB_PASSWORD',
            'API_KEY',
            'SECRET_KEY',
            'PRIVATE_KEY',
            'MAIL_PASSWORD',
            'REDIS_PASSWORD',
            'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY',
            'STRIPE_SECRET',
            'PUBLISHABLE_KEY',
            'JWT_SECRET',
            'ENCRYPTION_KEY',
            'APP_KEY',
        ];
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
        foreach ($this->sensitiveKeys as $key) {
            if (empty(env($key))) {
                $this->addFinding([
                    'package' => 'environment',
                    'title' => "Missing sensitive environment variable: {$key}",
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
        return strpos($gitignore, '.env') !== false;
    }
}