<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Reporters;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\ValueObjects\AuditReport;

final class JunitReporter implements ReportFormatter
{
    public function format(AuditReport $auditReport): string
    {
        $cases = [];

        foreach ($auditReport->errors() as $auditError) {
            $cases[] = sprintf(
                '  <testcase classname="%s" name="%s"><error message="%s">%s</error></testcase>',
                $this->escape('warden.' . $auditError->audit),
                $this->escape($auditError->code),
                $this->escape($auditError->message),
                $this->escape($auditError->message),
            );
        }

        foreach ($auditReport->findings() as $finding) {
            $className = $this->escape('warden.' . $finding->source);
            $name = $this->escape($finding->id . ':' . $finding->fingerprint());
            if ($finding->blocking) {
                $cases[] = sprintf(
                    '  <testcase classname="%s" name="%s"><failure type="%s" message="%s">%s</failure></testcase>',
                    $className,
                    $name,
                    $this->escape($finding->severity->value),
                    $this->escape($finding->title),
                    $this->escape($finding->description),
                );
            } else {
                $cases[] = sprintf(
                    '  <testcase classname="%s" name="%s"><system-out>%s</system-out></testcase>',
                    $className,
                    $name,
                    $this->escape($finding->description),
                );
            }
        }

        if ($cases === []) {
            $cases[] = '  <testcase classname="warden" name="security-audit" />';
        }

        return sprintf(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"Warden Security Audit\" tests=\"%d\" failures=\"%d\" errors=\"%d\">\n%s\n</testsuite>\n",
            count($cases),
            count(array_filter($auditReport->findings(), static fn ($finding): bool => $finding->blocking)),
            count($auditReport->errors()),
            implode("\n", $cases),
        );
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }
}
