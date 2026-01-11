<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditService;
use Dgtlss\Warden\ValueObjects\Finding;

abstract class AbstractAuditService implements AuditService
{
    /**
     * @var array<int, Finding>
     */
    protected array $findings = [];

    abstract public function run(): bool;

    abstract public function getName(): string;

    /**
     * @return array<int, Finding>
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    /**
     * Add a finding to the findings list.
     *
     * @param Finding|array<string, mixed> $finding
     */
    protected function addFinding(Finding|array $finding): void
    {
        if (is_array($finding)) {
            $finding = Finding::fromArray(array_merge($finding, [
                'source' => $this->getName()
            ]));
        }

        $this->findings[] = $finding;
    }
}