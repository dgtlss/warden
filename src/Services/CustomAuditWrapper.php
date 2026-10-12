<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Contracts\CustomAudit;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;

final readonly class CustomAuditWrapper implements AuditServiceInterface
{
    public function __construct(private CustomAudit $customAudit)
    {
    }

    public function getName(): string
    {
        return $this->customAudit->getName();
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        if (!$this->customAudit->shouldRun($auditContext)) {
            return new AuditResult($this->getName(), coverage: ['scanned' => 0, 'skipped' => 1, 'errors' => 0]);
        }

        return $this->customAudit->run($auditContext);
    }
}
