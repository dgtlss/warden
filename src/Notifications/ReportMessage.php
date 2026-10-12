<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Notifications;

use Dgtlss\Warden\ValueObjects\AuditReport;

final class ReportMessage
{
    public static function title(AuditReport $auditReport, ?int $appNameLimit = null): string
    {
        $status = $auditReport->errors() !== [] ? 'Incomplete scan' : ($auditReport->findings() === [] ? 'Completed scan' : 'Findings detected');

        $appName = (string) config('warden.app_name', 'Application');
        if ($appNameLimit !== null) {
            $appName = mb_substr($appName, 0, $appNameLimit, 'UTF-8');
        }

        return sprintf('[%s] Warden: %s', $appName, $status);
    }

    public static function body(AuditReport $auditReport): string
    {
        $findings = $auditReport->findings();
        $blocking = count(array_filter($findings, static fn ($finding): bool => $finding->blocking));
        $lines = [sprintf('%d blocking findings, %d advisory findings, %d scan errors. Profile: %s; scope: %s.',
            $blocking, count($findings) - $blocking, count($auditReport->errors()), $auditReport->context->profile, $auditReport->context->scope)];
        if ($auditReport->errors() !== []) {
            $lines[] = 'Scan incomplete: no all-clear result is available.';
        } elseif ($findings === []) {
            $lines[] = 'No active findings in the completed scan.';
        }

        foreach ($auditReport->errors() as $auditError) {
            $lines[] = sprintf('ERROR [%s/%s] %s', $auditError->audit, $auditError->code, $auditError->message);
        }

        foreach ($findings as $finding) {
            $location = $finding->path ?? $finding->package ?? $finding->source;
            if ($finding->line !== null) {
                $location .= ':' . $finding->line;
            }

            $lines[] = sprintf('%s %s [%s] %s (%s)', strtoupper($finding->severity->value),
                $finding->blocking ? 'blocking' : 'advisory', $finding->id, $finding->title, $location);
        }

        return implode("\n", $lines);
    }
}
