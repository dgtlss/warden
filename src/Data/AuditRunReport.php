<?php

namespace Dgtlss\Warden\Data;

class AuditRunReport
{
    /**
     * @param array<int, AuditResult> $results
     * @param array<int, array<string, mixed>> $findings
     * @param array<int, array<string, mixed>> $suppressedFindings
     * @param array<int, array<string, mixed>> $abandonedPackages
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public readonly array $results,
        public readonly array $findings,
        public readonly array $suppressedFindings,
        public readonly array $abandonedPackages,
        public readonly bool $hasFailures,
        public readonly float $durationMs,
        public readonly string $profile,
        public readonly array $metadata = [],
    ) {
    }

    public function totalFindings(): int
    {
        return count($this->findings);
    }

    /**
     * @return array<string, int>
     */
    public function severityCounts(): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
        ];

        foreach ($this->findings as $finding) {
            $severity = strtolower((string) ($finding['severity'] ?? 'low'));
            if (array_key_exists($severity, $counts)) {
                $counts[$severity]++;
            }
        }

        return $counts;
    }
}
