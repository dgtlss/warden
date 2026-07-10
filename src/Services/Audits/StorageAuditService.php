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
        foreach ($this->directories as $directory) {
            $path = base_path($directory);
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
