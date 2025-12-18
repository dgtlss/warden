<?php

namespace Dgtlss\Warden\Services\Audits;

abstract class AbstractAuditService
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

    protected function addFinding(array $finding): void
    {
        $this->findings[] = array_merge($finding, [
            'source' => $this->getName()
        ]);
    }
}