<?php

namespace Dgtlss\Warden\Services\Audits;

class StorageAuditService extends AbstractAuditService
{
    public function getName(): string
    {
        return 'storage';
    }

    public function run(): bool
    {
        $directories = [
            storage_path('framework'),
            storage_path('logs'),
            base_path('bootstrap/cache'),
        ];

        foreach ($directories as $path) {
            
            if (!file_exists($path)) {
                $this->addFinding([
                    'package' => 'storage',
                    'title' => 'Missing directory: ' . $path,
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null
                ]);
                continue;
            }

            if (!is_writable($path)) {
                $this->addFinding([
                    'package' => 'storage',
                    'title' => 'Directory not writable: ' . $path,
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null
                ]);
            }
        }

        return true;
    }
}
