<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Contracts;

use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;

interface AuditServiceInterface
{
    public function getName(): string;

    public function run(AuditContext $auditContext): AuditResult;
}
