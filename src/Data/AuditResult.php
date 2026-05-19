<?php

namespace Dgtlss\Warden\Data;

class AuditResult
{
    /**
     * @param array<int, Finding> $findings
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public readonly string $auditId,
        public readonly string $auditName,
        public readonly bool $success,
        public readonly array $findings,
        public readonly float $durationMs,
        public readonly bool $cached = false,
        public readonly array $metadata = [],
    ) {
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function findingsToArray(): array
    {
        return array_map(
            static fn (Finding $finding): array => $finding->toArray(),
            $this->findings
        );
    }
}
