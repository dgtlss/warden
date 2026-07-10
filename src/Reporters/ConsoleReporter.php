<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Reporters;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use Symfony\Component\Console\Formatter\OutputFormatter;

final class ConsoleReporter implements ReportFormatter
{
    private const WIDTH = 96;

    private const CHECK_TABLE_WIDTH = 112;

    private readonly OutputFormatter $outputFormatter;

    public function __construct(bool $decorated = false)
    {
        $this->outputFormatter = new OutputFormatter($decorated);
    }

    public function format(AuditReport $auditReport): string
    {
        $findings = $auditReport->findings();
        $errors = $auditReport->errors();
        $duration = array_sum(array_map(static fn ($audit): float => $audit->durationMs, $auditReport->audits));
        $completed = count(array_filter($auditReport->audits, static fn ($audit): bool => $audit->succeeded()));
        $failed = count($auditReport->audits) - $completed;
        $blocking = count(array_filter($findings, static fn (Finding $finding): bool => $finding->blocking));

        $lines = [
            '',
            '<fg=cyan;options=bold>WARDEN 2.0</>  <options=bold>SECURITY AUDIT</>',
            sprintf(
                '<fg=gray>%s profile  •  %s dependencies  •  %s</>',
                $this->escape(strtoupper($auditReport->context->profile)),
                $this->escape($auditReport->context->scope),
                $this->duration($duration),
            ),
            '',
            sprintf(
                '<fg=green>%d audit%s completed</>%s  •  <options=bold>%d active finding%s</>  •  %d ignored',
                $completed,
                $completed === 1 ? '' : 's',
                $failed > 0 ? sprintf('  •  <fg=red>%d failed</>', $failed) : '',
                count($findings),
                count($findings) === 1 ? '' : 's',
                count($auditReport->ignoredFindings),
            ),
            sprintf(
                '%s  •  <options=bold>%d blocking</>  •  <fg=gray>%d advisory</>',
                $this->severitySummary($findings),
                $blocking,
                count($findings) - $blocking,
            ),
        ];

        if ($auditReport->audits !== []) {
            $lines[] = '';
            $lines[] = '<options=bold>CHECK RESULTS</>';
            $lines[] = '<fg=gray>' . str_repeat('─', self::CHECK_TABLE_WIDTH) . '</>';
            $lines[] = '<fg=gray>' . $this->escape(sprintf(
                '   %-20s %-13s %-26s %-26s %-10s %9s',
                'CHECK',
                'RESULT',
                'SEVERITY',
                'DISPOSITION',
                'ERRORS',
                'TIME',
            )) . '</>';
            foreach ($auditReport->audits as $audit) {
                $lines[] = $this->auditSummary($audit);
            }
        }

        if ($errors !== []) {
            $lines[] = '';
            $lines[] = '<fg=red;options=bold>SCAN INCOMPLETE</>  <fg=red>' . count($errors) . ' error' . (count($errors) === 1 ? '' : 's') . '</>';
            $lines[] = '<fg=red>' . str_repeat('─', 72) . '</>';
            foreach ($errors as $error) {
                $lines[] = sprintf(
                    '<fg=red>●</> <options=bold>%s</>  <fg=gray>%s</>',
                    $this->escape($this->auditLabel($error->audit)),
                    $this->escape($error->code),
                );
                array_push($lines, ...$this->detail('Message', $error->message));
                $lines[] = '';
            }
        }

        if ($findings === []) {
            $lines[] = '';
            $lines[] = $errors === []
                ? '<fg=green;options=bold>✓ No active security findings.</>'
                : '<fg=gray>No findings were reported before the scan stopped.</>';

            return $this->render($lines);
        }

        foreach ($auditReport->audits as $audit) {
            if ($audit->findings === []) {
                continue;
            }

            $lines[] = '';
            $lines[] = sprintf(
                '<fg=cyan;options=bold>%s</>  <options=bold>%d finding%s</>  <fg=gray>• %s</>%s',
                $this->escape($this->auditLabel($audit->audit)),
                count($audit->findings),
                count($audit->findings) === 1 ? '' : 's',
                $this->escape($this->plainSeveritySummary($audit->findings)),
                $audit->succeeded() ? '' : '  <fg=red;options=bold>INCOMPLETE</>',
            );
            $lines[] = '<fg=cyan>' . str_repeat('━', 72) . '</>';

            $groups = $this->groups($audit->findings);
            foreach (['critical', 'high', 'medium', 'low'] as $severity) {
                $section = array_values(array_filter($groups, static fn (array $group): bool => $group['severity'] === $severity));
                if ($section === []) {
                    continue;
                }

                $sectionCount = array_sum(array_map(static fn (array $group): int => count($group['findings']), $section));
                $lines[] = sprintf('%s  <fg=gray>%d</>', $this->severityLabel($severity), $sectionCount);

                foreach ($section as $group) {
                    $count = count($group['findings']);
                    $suffix = $count > 1 ? sprintf('  <fg=gray>· %d occurrences</>', $count) : '';
                    $advisory = $group['blocking'] ? '' : '  <fg=yellow>ADVISORY</>';
                    $lines[] = sprintf('  ● <options=bold>%s</>%s%s', $this->escape($group['title']), $suffix, $advisory);
                    $lines[] = sprintf('    <fg=gray>%s</>', $this->escape($group['id']));

                    $descriptions = array_values(array_unique(array_map(static fn (Finding $finding): string => $finding->description, $group['findings'])));
                    if (count($descriptions) === 1) {
                        array_push($lines, ...$this->detail('Why', $descriptions[0]));
                    }

                    $packages = array_values(array_unique(array_filter(array_map(static fn (Finding $finding): ?string => $finding->package, $group['findings']))));
                    if ($packages !== []) {
                        array_push($lines, ...$this->detail('Package', implode(', ', $packages)));
                    }

                    $locations = $this->locations($group['findings']);
                    if ($locations !== []) {
                        array_push($lines, ...$this->locationLines($locations));
                    }

                    $references = array_values(array_unique(array_filter(array_map(static fn (Finding $finding): ?string => $finding->reference, $group['findings']))));
                    foreach ($references as $reference) {
                        array_push($lines, ...$this->detail('Reference', $reference));
                    }

                    if ($group['remediation'] !== null) {
                        array_push($lines, ...$this->detail('Fix', $group['remediation'], '<fg=green>'));
                    }

                    $lines[] = '';
                }
            }
        }

        if ($auditReport->ignoredFindings !== []) {
            $lines[] = sprintf(
                '<fg=gray>%d finding%s suppressed by reviewed policy or baseline.</>',
                count($auditReport->ignoredFindings),
                count($auditReport->ignoredFindings) === 1 ? '' : 's',
            );
        }

        return $this->render($lines);
    }

    /**
     * @param list<Finding> $findings
     * @return list<array{severity: string, blocking: bool, id: string, title: string, remediation: ?string, findings: list<Finding>}>
     */
    private function groups(array $findings): array
    {
        $groups = [];
        foreach ($findings as $finding) {
            $key = hash('sha256', implode('|', [
                $finding->severity->value,
                $finding->blocking ? 'blocking' : 'advisory',
                $finding->id,
                $finding->title,
                $finding->remediation ?? '',
            ]));
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'severity' => $finding->severity->value,
                    'blocking' => $finding->blocking,
                    'id' => $finding->id,
                    'title' => $finding->title,
                    'remediation' => $finding->remediation,
                    'findings' => [],
                ];
            }

            $groups[$key]['findings'][] = $finding;
        }

        return array_values($groups);
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private function locations(array $findings): array
    {
        $locations = [];
        foreach ($findings as $finding) {
            if ($finding->path === null) {
                continue;
            }

            $locations[] = $finding->path . ($finding->line === null ? '' : ':' . $finding->line);
        }

        return array_values(array_unique($locations));
    }

    /**
     * @param list<string> $locations
     * @return list<string>
     */
    private function locationLines(array $locations): array
    {
        $lines = [];
        foreach ($locations as $index => $location) {
            $branch = $index === array_key_last($locations) ? '└─' : '├─';
            $label = $index === 0 ? '    Where      ' : '               ';
            $lines[] = sprintf('<fg=gray>%s%s %s</>', $label, $branch, $this->escape($location));
        }

        return $lines;
    }

    /** @return list<string> */
    private function detail(string $label, string $text, string $style = '<fg=gray>'): array
    {
        $prefix = '    ' . str_pad($label, 10) . ' ';
        $wrapped = explode("\n", wordwrap($text, self::WIDTH - strlen($prefix), "\n", false));
        $lines = [];
        foreach ($wrapped as $index => $line) {
            $lines[] = sprintf('%s%s%s</>', $style, $index === 0 ? $prefix : str_repeat(' ', strlen($prefix)), $this->escape($line));
        }

        return $lines;
    }

    /** @param list<Finding> $findings */
    private function severitySummary(array $findings): string
    {
        $parts = [];
        foreach (['critical', 'high', 'medium', 'low'] as $severity) {
            $count = count(array_filter($findings, static fn (Finding $finding): bool => $finding->severity->value === $severity));
            if ($count > 0) {
                $parts[] = sprintf('%s %d', $this->severityLabel($severity), $count);
            }
        }

        return $parts === [] ? '<fg=green>Clean</>' : implode('  ', $parts);
    }

    private function auditSummary(AuditResult $auditResult): string
    {
        $status = $auditResult->succeeded() ? '<fg=green>✓</>' : '<fg=red>✗</>';
        $label = str_pad($this->auditLabel($auditResult->audit), 20);
        $findingCount = count($auditResult->findings);
        $resultText = match (true) {
            $findingCount > 0 => sprintf('%d finding%s', $findingCount, $findingCount === 1 ? '' : 's'),
            !$auditResult->succeeded() => 'incomplete',
            default => 'clean',
        };
        $result = str_pad($resultText, 13);
        $counts = $this->severityCounts($auditResult->findings);
        $severity = $findingCount === 0
            ? str_repeat(' ', 26)
            : sprintf('C %3d  H %3d  M %3d  L %3d', $counts['critical'], $counts['high'], $counts['medium'], $counts['low']);
        $blocking = count(array_filter($auditResult->findings, static fn (Finding $finding): bool => $finding->blocking));
        $disposition = $findingCount === 0
            ? str_repeat(' ', 26)
            : sprintf('%3d blocking  %3d advisory', $blocking, $findingCount - $blocking);
        $errorCount = count($auditResult->errors);
        $errors = str_pad($errorCount === 0 ? '' : sprintf('%d error%s', $errorCount, $errorCount === 1 ? '' : 's'), 10);
        $time = str_pad($this->duration($auditResult->durationMs), 9, ' ', STR_PAD_LEFT);
        $resultStyle = match (true) {
            !$auditResult->succeeded() && $findingCount === 0 => 'red',
            $findingCount === 0 => 'green',
            default => 'default',
        };

        return sprintf(
            '%s  <options=bold>%s</> <fg=%s>%s</> <fg=gray>%s</> <fg=gray>%s</> <fg=red>%s</> <fg=gray>%s</>',
            $status,
            $this->escape($label),
            $resultStyle,
            $this->escape($result),
            $this->escape($severity),
            $this->escape($disposition),
            $this->escape($errors),
            $this->escape($time),
        );
    }

    /** @param list<Finding> $findings */
    private function plainSeveritySummary(array $findings): string
    {
        $labels = ['critical' => 'C', 'high' => 'H', 'medium' => 'M', 'low' => 'L'];
        $counts = $this->severityCounts($findings);
        $parts = [];
        foreach ($labels as $severity => $label) {
            $count = $counts[$severity];
            if ($count > 0) {
                $parts[] = $label . ' ' . $count;
            }
        }

        return implode('  ', $parts);
    }

    /**
     * @param list<Finding> $findings
     * @return array{critical: int, high: int, medium: int, low: int}
     */
    private function severityCounts(array $findings): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($findings as $finding) {
            $counts[$finding->severity->value]++;
        }

        return $counts;
    }

    private function auditLabel(string $audit): string
    {
        return strtoupper(str_replace('-', ' ', $audit));
    }

    private function severityLabel(string $severity): string
    {
        $color = match ($severity) {
            'critical' => 'red',
            'high' => 'magenta',
            'medium' => 'yellow',
            default => 'blue',
        };

        return sprintf('<fg=%s;options=bold>%s</>', $color, strtoupper($severity));
    }

    private function duration(float $milliseconds): string
    {
        return $milliseconds >= 1000
            ? number_format($milliseconds / 1000, 2) . 's'
            : number_format($milliseconds, 1) . 'ms';
    }

    /** @param list<string> $lines */
    private function render(array $lines): string
    {
        return $this->outputFormatter->format(implode(PHP_EOL, $lines) . PHP_EOL) ?? '';
    }

    private function escape(string $value): string
    {
        return OutputFormatter::escape($value);
    }
}
