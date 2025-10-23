<?php

namespace Dgtlss\Warden\Services\Audits;

class StorageAuditService extends AbstractAuditService
{
    private $directories = [];

    public function getName(): string
    {
        return 'storage';
    }

    /**
     * Get the default configuration for this audit.
     *
     * @return array
     */
    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'directories' => env('WARDEN_STORAGE_DIRECTORIES') ? explode(',', env('WARDEN_STORAGE_DIRECTORIES')) : [
                'storage/framework',
                'storage/logs',
                'bootstrap/cache',
            ],
            'check_permissions' => env('WARDEN_STORAGE_CHECK_PERMISSIONS', true),
            'check_existence' => env('WARDEN_STORAGE_CHECK_EXISTENCE', true),
            'required_permissions' => env('WARDEN_STORAGE_REQUIRED_PERMISSIONS', '755'),
        ]);
    }

    /**
     * Initialize the audit service with configuration.
     *
     * @param array $config
     * @return void
     */
    public function initialize(array $config = []): void
    {
        parent::initialize($config);
        $this->directories = $this->getConfigValue('directories', $this->directories);
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
