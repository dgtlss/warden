<?php

namespace Dgtlss\Warden\Services\Audits;

abstract class AbstractAuditService
{
    protected $findings = [];
    
    abstract public function run(): bool;
    abstract public function getName(): string;
    
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