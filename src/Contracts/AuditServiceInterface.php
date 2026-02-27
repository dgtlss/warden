<?php

namespace Dgtlss\Warden\Contracts;

interface AuditServiceInterface
{
    public function run(): bool;

    public function getName(): string;

    /**
     * @return array<array<string, mixed>>
     */
    public function getFindings(): array;
}
