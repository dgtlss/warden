<?php

namespace Dgtlss\Warden\Notifications\Concerns;

trait HasSeverityHelpers
{
    /**
     * @param array<array<string, mixed>> $findings
     * @return array{critical: int, high: int, medium: int, low: int}
     */
    protected function getSeverityCounts(array $findings): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            if (isset($counts[$severity])) {
                $counts[$severity]++;
            }
        }

        return $counts;
    }

    /** @param array<array<string, mixed>> $findings */
    protected function getHighestSeverity(array $findings): string
    {
        $severityLevels = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $highest = 'low';
        $highestLevel = 1;

        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            $level = $severityLevels[$severity] ?? 1;

            if ($level > $highestLevel) {
                $highest = $severity;
                $highestLevel = $level;
            }
        }

        return $highest;
    }

    protected function getSeverityEmoji(string $severity): string
    {
        return match ($severity) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium' => '🟡',
            'low' => '🟢',
            default => '⚪',
        };
    }

    /**
     * @param array<array<string, mixed>> $findings
     * @return array<string, array<array<string, mixed>>>
     */
    protected function groupFindingsBySource(array $findings): array
    {
        $grouped = [];

        foreach ($findings as $finding) {
            $source = $finding['source'] ?? 'unknown';
            $grouped[$source][] = $finding;
        }

        return $grouped;
    }
}
