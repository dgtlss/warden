<?php

namespace Dgtlss\Warden\Services\Audits;

class StorageAuditService extends AbstractAuditService
{
    /**
     * @var array<string>
     */
    private array $directories = [
        'storage/framework',
        'storage/logs',
        'bootstrap/cache',
    ];

    public function getName(): string
    {
        return 'storage';
    }

    public function run(): bool
    {
        foreach ($this->directories as $directory) {
            $path = base_path($directory);
            
            if (!file_exists($path)) {
                $this->addFinding([
                    'package' => 'storage',
                    'title' => 'Missing directory: ' . $directory,
                    'rule_id' => sprintf('storage.directory.%s.missing', str_replace(['/', '\\'], '.', $directory)),
                    'category' => 'filesystem',
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null,
                    'description' => sprintf('The required Laravel writable directory [%s] is missing.', $directory),
                    'file' => $directory,
                ]);
                continue;
            }

            if (!is_writable($path)) {
                $this->addFinding([
                    'package' => 'storage',
                    'title' => 'Directory not writable: ' . $directory,
                    'rule_id' => sprintf('storage.directory.%s.not-writable', str_replace(['/', '\\'], '.', $directory)),
                    'category' => 'filesystem',
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null,
                    'description' => sprintf('The Laravel runtime directory [%s] is not writable.', $directory),
                    'file' => $directory,
                ]);
            }
        }

        return true;
    }
}
