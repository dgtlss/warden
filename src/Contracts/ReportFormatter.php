<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Contracts;

use Dgtlss\Warden\ValueObjects\AuditReport;

interface ReportFormatter
{
    public function format(AuditReport $auditReport): string;
}
