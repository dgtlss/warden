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
    /** @var list<string> */
    private array $directories = ['storage/framework', 'storage/logs', 'bootstrap/cache'];

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
        $envPath = base_path('.env');
        if (is_file($envPath)) {
            $permissions = fileperms($envPath);
            if (is_int($permissions) && (($permissions & 0004) !== 0 || ($permissions & 0002) !== 0)) {
                $findings[] = new Finding(
                    id: 'deployment.env.permissions',
                    source: $this->getName(),
                    title: 'Environment file permissions are too broad',
                    severity: Severity::Medium,
                    description: sprintf('.env permissions are %s and permit world read or write access.', substr(sprintf('%o', $permissions), -4)),
                    remediation: 'Restrict .env to the deployment owner/group, normally mode 600 or 640.',
                    path: '.env',
                    blocking: false,
                    identity: 'env-permissions',
                );
            }
        }

        foreach ($this->directories as $directory) {
            $path = base_path($directory);
            $permissions = @fileperms($path);
            if (is_int($permissions) && ($permissions & 0002) !== 0) {
                $findings[] = new Finding(
                    id: 'deployment.path.world-writable',
                    source: $this->getName(),
                    title: sprintf('Deployment path is world-writable: %s', $directory),
                    severity: Severity::Medium,
                    description: 'Any local user may modify files used by the Laravel runtime.',
                    remediation: 'Grant write access only to the deployment user or service group.',
                    path: $directory,
                    blocking: false,
                    identity: $directory,
                );
            }

            if (!is_dir($path) || !is_writable($path)) {
                $findings[] = new Finding(
                    id: 'deployment.storage.not-writable',
                    source: $this->getName(),
                    title: sprintf('Required directory is not writable: %s', $directory),
                    severity: Severity::Low,
                    description: 'Laravel may fail to write caches, compiled views, sessions, or logs.',
                    remediation: 'Grant the deployment user write access without making the directory world-writable.',
                    path: $directory,
                    blocking: false,
                );
            }
        }

        return AuditResult::complete($this->getName(), $findings);
    }
}
