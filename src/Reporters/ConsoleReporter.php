<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Reporters;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\ValueObjects\AuditReport;

final class ConsoleReporter implements ReportFormatter
{
    public function format(AuditReport $auditReport): string
    {
        $lines = [
            'Warden 2.0 Security Audit',
            sprintf('Profile: %s | Scope: %s', $auditReport->context->profile, $auditReport->context->scope),
            '',
        ];

        foreach ($auditReport->audits as $audit) {
            $lines[] = sprintf(
                '[%s] %s (%sms, %d findings)',
                $audit->succeeded() ? 'PASS' : 'FAIL',
                $audit->audit,
                number_format($audit->durationMs, 1),
                count($audit->findings),
            );
        }

        if ($auditReport->errors() !== []) {
            $lines[] = '';
            $lines[] = sprintf('%d audit/configuration error(s):', count($auditReport->errors()));
            foreach ($auditReport->errors() as $error) {
                $lines[] = sprintf('  - [%s:%s] %s', $error->audit, $error->code, $error->message);
            }
        }

        $lines[] = '';
        if ($auditReport->findings() === []) {
            $lines[] = 'No active security findings.';
        } else {
            $lines[] = sprintf('%d active finding(s):', count($auditReport->findings()));
            foreach ($auditReport->findings() as $finding) {
                $location = $finding->path === null ? '' : sprintf(' [%s%s]', $finding->path, $finding->line === null ? '' : ':' . $finding->line);
                $lines[] = sprintf(
                    '  - %s %s: %s%s%s',
                    strtoupper($finding->severity->value),
                    $finding->id,
                    $finding->title,
                    $location,
                    $finding->blocking ? '' : ' [ADVISORY — non-blocking]',
                );
                $lines[] = '    ' . $finding->description;
                if ($finding->remediation !== null) {
                    $lines[] = '    Fix: ' . $finding->remediation;
                }
            }
        }

        if ($auditReport->ignoredFindings !== []) {
            $lines[] = '';
            $lines[] = sprintf('%d finding(s) suppressed by reviewed policy or baseline.', count($auditReport->ignoredFindings));
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }
}
