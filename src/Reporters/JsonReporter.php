<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Reporters;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\ValueObjects\AuditReport;
use JsonException;

final class JsonReporter implements ReportFormatter
{
    /** @throws JsonException */
    public function format(AuditReport $auditReport): string
    {
        return json_encode($auditReport, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
    }
}
