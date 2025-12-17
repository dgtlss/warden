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
                    'title' => "Missing directory: {$directory}",
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null
                ]);
                continue;
            }

            if (!is_writable($path)) {
                $this->addFinding([
                    'package' => 'storage',
                    'title' => "Directory not writable: {$directory}",
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null
                ]);
            }
        }

        return true;
    }
}
