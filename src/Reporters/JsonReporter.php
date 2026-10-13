<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Reporters;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use JsonException;

final class JsonReporter implements ReportFormatter
{
    public function __construct(private readonly bool $extended = false)
    {
    }

    /** @throws JsonException */
    public function format(AuditReport $auditReport): string
    {
        $data = $auditReport->jsonSerialize();
        if ($this->extended) {
            $data['schema_version'] = '2.1.0';
            $data['gate'] = ['fail_on' => $auditReport->failOn, 'exit_code' => $auditReport->exitCode()];
            $data['audits'] = array_map(
                static fn (AuditResult $auditResult): array => [...$auditResult->jsonSerialize(), 'coverage' => $auditResult->coverage],
                $auditReport->audits,
            );
        }

        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
    }
}
