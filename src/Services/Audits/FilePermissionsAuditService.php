<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Enums\Severity;

class FilePermissionsAuditService extends AbstractAuditService
{
    /**
     * Files and their maximum allowed permissions.
     *
     * @var array<string, array<string, mixed>>
     */
    protected array $securityCriticalFiles = [
        '.env' => [
            'max_permissions' => 0600,
            'severity' => Severity::CRITICAL,
            'description' => 'Environment file contains sensitive credentials',
        ],
        '.env.example' => [
            'max_permissions' => 0644,
            'severity' => Severity::LOW,
            'description' => 'Example environment file',
        ],
        'config/database.php' => [
            'max_permissions' => 0644,
            'severity' => Severity::HIGH,
            'description' => 'Database configuration file',
        ],
        'config/auth.php' => [
            'max_permissions' => 0644,
            'severity' => Severity::MEDIUM,
            'description' => 'Authentication configuration file',
        ],
    ];

    /**
     * Directories that should not be world-writable.
     *
     * @var array<string, array<string, mixed>>
     */
    protected array $protectedDirectories = [
        'config' => [
            'severity' => Severity::HIGH,
            'description' => 'Configuration directory',
        ],
        'app' => [
            'severity' => Severity::MEDIUM,
            'description' => 'Application code directory',
        ],
        'routes' => [
            'severity' => Severity::MEDIUM,
            'description' => 'Routes directory',
        ],
    ];

    public function run(): bool
    {
        $this->checkFilePermissions();
        $this->checkDirectoryPermissions();
        $this->checkPublicDirectory();

        return true;
    }

    public function getName(): string
    {
        return 'File Permissions';
    }

    /**
     * Check permissions on security-critical files.
     */
    protected function checkFilePermissions(): void
    {
        $basePath = base_path();

        foreach ($this->securityCriticalFiles as $file => $config) {
            $filePath = $basePath . '/' . $file;

            if (!file_exists($filePath)) {
                continue;
            }

            $currentPerms = fileperms($filePath) & 0777;
            $maxPerms = $config['max_permissions'];
            $severity = $config['severity'];
            $description = $config['description'];

            if (!is_int($maxPerms) || !$severity instanceof Severity || !is_string($description)) {
                continue;
            }

            if ($currentPerms > $maxPerms) {
                $this->addFinding([
                    'package' => 'File System',
                    'title' => sprintf(
                        'Insecure file permissions on %s (%04o, should be %04o or less)',
                        $file,
                        $currentPerms,
                        $maxPerms
                    ),
                    'severity' => $severity,
                    'cve' => null,
                    'affected_versions' => null,
                    'error' => sprintf(
                        '%s has overly permissive permissions. Run: chmod %04o %s',
                        $description,
                        $maxPerms,
                        $file
                    ),
                ]);
            }
        }
    }

    /**
     * Check directory permissions.
     */
    protected function checkDirectoryPermissions(): void
    {
        $basePath = base_path();

        foreach ($this->protectedDirectories as $directory => $config) {
            $dirPath = $basePath . '/' . $directory;

            if (!is_dir($dirPath)) {
                continue;
            }

            $currentPerms = fileperms($dirPath) & 0777;

            $severity = $config['severity'];
            $description = $config['description'];

            if (!$severity instanceof Severity || !is_string($description)) {
                continue;
            }

            // Check if world-writable (others have write permission)
            if (($currentPerms & 0002) !== 0) {
                $this->addFinding([
                    'package' => 'File System',
                    'title' => sprintf(
                        'World-writable directory: %s (%04o)',
                        $directory,
                        $currentPerms
                    ),
                    'severity' => $severity,
                    'cve' => null,
                    'affected_versions' => null,
                    'error' => sprintf(
                        '%s is world-writable, allowing any user to modify files. Run: chmod o-w %s',
                        $description,
                        $directory
                    ),
                ]);
            }
        }
    }

    /**
     * Check for sensitive files in the public directory.
     */
    protected function checkPublicDirectory(): void
    {
        $publicPath = public_path();

        $sensitiveFiles = [
            '.env',
            '.git',
            'composer.json',
            'composer.lock',
            'package.json',
            'package-lock.json',
            'phpunit.xml',
            '.env.example',
        ];

        foreach ($sensitiveFiles as $file) {
            $filePath = $publicPath . '/' . $file;

            if (file_exists($filePath)) {
                $this->addFinding([
                    'package' => 'File System',
                    'title' => sprintf('Sensitive file exposed in public directory: %s', $file),
                    'severity' => Severity::CRITICAL,
                    'cve' => null,
                    'affected_versions' => null,
                    'error' => sprintf(
                        'The file %s should never be in the public directory. Remove it immediately to prevent information disclosure.',
                        $file
                    ),
                ]);
            }
        }
    }
}
