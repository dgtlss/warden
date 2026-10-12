<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Contracts;

use Dgtlss\Warden\ValueObjects\AuditReport;

interface ReportNotificationChannel extends NotificationChannel
{
    public function sendReport(AuditReport $auditReport): void;
}
