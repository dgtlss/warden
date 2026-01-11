<?php

namespace Dgtlss\Warden\Contracts;

interface AuditService
{
    /**
     * Run the audit and return success status.
     */
    public function run(): bool;

    /**
     * Get the name of this audit service.
     */
    public function getName(): string;

    /**
     * Get all findings from the audit.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getFindings(): array;
}
