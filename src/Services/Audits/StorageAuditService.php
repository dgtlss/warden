<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;

final class StorageAuditService implements AuditServiceInterface
{
    public function getName(): string
    {
        return 'storage';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        if ($auditContext->profile !== 'production') {
            return AuditResult::complete($this->getName());
        }

        $findings = [];
        $envPath = app()->environmentFilePath();
        if (is_file($envPath)) {
            $permissions = fileperms($envPath);
            if (is_int($permissions) && (($permissions & 0004) !== 0 || ($permissions & 0002) !== 0)) {
                $findings[] = new Finding(
                    id: 'deployment.env.permissions',
                    source: $this->getName(),
                    title: 'Environment file permissions are too broad',
                    severity: Severity::Medium,
                    description: sprintf('%s permissions are %s and permit world read or write access.', $this->relativePath($envPath), substr(sprintf('%o', $permissions), -4)),
                    remediation: 'Restrict .env to the deployment owner/group, normally mode 600 or 640.',
                    path: $this->relativePath($envPath),
                    blocking: false,
                    identity: 'env-permissions',
                );
            }
        }

        $directories = [
            'storage/framework' => storage_path('framework'),
            'storage/logs' => storage_path('logs'),
            'bootstrap/cache' => app()->bootstrapPath('cache'),
        ];
        foreach ($directories as $directory => $path) {
            $relativePath = $this->relativePath($path);
            $permissions = @fileperms($path);
            if (is_int($permissions) && ($permissions & 0002) !== 0) {
                $findings[] = new Finding(
                    id: 'deployment.path.world-writable',
                    source: $this->getName(),
                    title: sprintf('Deployment path is world-writable: %s', $relativePath),
                    severity: Severity::Medium,
                    description: 'Any local user may modify files used by the Laravel runtime.',
                    remediation: 'Grant write access only to the deployment user or service group.',
                    path: $relativePath,
                    blocking: false,
                    identity: $directory,
                );
            }

            if (!is_dir($path) || !is_writable($path)) {
                $findings[] = new Finding(
                    id: 'deployment.storage.not-writable',
                    source: $this->getName(),
                    title: sprintf('Required directory is not writable: %s', $relativePath),
                    severity: Severity::Low,
                    description: 'Laravel may fail to write caches, compiled views, sessions, or logs.',
                    remediation: 'Grant the deployment user write access without making the directory world-writable.',
                    path: $relativePath,
                    blocking: false,
                );
            }
        }

        return AuditResult::complete($this->getName(), $findings);
    }

    private function relativePath(string $path): string
    {
        $path = realpath($path) ?: $path;
        $root = rtrim(realpath(base_path()) ?: base_path(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        return str_starts_with($path, $root) ? substr($path, strlen($root)) : $path;
    }
}
