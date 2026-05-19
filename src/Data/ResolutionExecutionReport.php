<?php

namespace Dgtlss\Warden\Data;

class ResolutionExecutionReport
{
    /**
     * @param array<int, array<string, mixed>> $applied
     * @param array<int, array<string, mixed>> $skipped
     * @param array<int, array<string, mixed>> $verification
     */
    public function __construct(
        public readonly bool $success,
        public readonly array $applied,
        public readonly array $skipped,
        public readonly array $verification,
        public readonly ?string $failureMessage = null,
        public readonly ?AuditRunReport $postAuditReport = null,
    ) {
    }
}
