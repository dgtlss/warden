<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Reporters;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\ValueObjects\AuditReport;

final class GitHubReporter implements ReportFormatter
{
    public function format(AuditReport $auditReport): string
    {
        $lines = [];
        foreach ($auditReport->errors() as $auditError) {
            $lines[] = sprintf('::error title=%s::%s', $this->key($auditError->code), $this->message($auditError->message));
        }

        foreach ($auditReport->findings() as $finding) {
            $level = in_array($finding->severity->value, ['critical', 'high'], true) ? 'error' : 'warning';
            $properties = ['title=' . $this->key($finding->id)];
            if ($finding->path !== null) {
                $properties[] = 'file=' . $this->key($finding->path);
            }

            if ($finding->line !== null) {
                $properties[] = 'line=' . $finding->line;
            }

            $lines[] = sprintf('::%s %s::%s', $level, implode(',', $properties), $this->message($finding->title . ' — ' . $finding->description));
        }

        if ($lines === []) {
            $lines[] = '::notice title=Warden::No security issues found.';
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    private function key(string $value): string
    {
        return str_replace(['%', "\r", "\n", ':', ','], ['%25', '%0D', '%0A', '%3A', '%2C'], $value);
    }

    private function message(string $value): string
    {
        return str_replace(['%', "\r", "\n"], ['%25', '%0D', '%0A'], $value);
    }
}
