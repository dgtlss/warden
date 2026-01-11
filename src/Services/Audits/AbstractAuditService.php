<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditService;

abstract class AbstractAuditService implements AuditService
{
    /**
     * @var array<array<string, mixed>>
     */
    protected array $findings = [];

    abstract public function run(): bool;

    abstract public function getName(): string;

    /**
     * @return array<array<string, mixed>>
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    /**
     * Add a finding to the findings list.
     *
     * @param array<string, mixed> $finding
     */
    protected function addFinding(array $finding): void
    {
        $this->findings[] = array_merge($finding, [
            'source' => $this->getName()
        ]);
    }
}