<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Contracts;

use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;

interface CustomAudit
{
    public function getName(): string;

    public function getDescription(): string;

    public function shouldRun(AuditContext $auditContext): bool;

    public function run(AuditContext $auditContext): AuditResult;
}
