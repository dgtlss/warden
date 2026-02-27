<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\CustomAudit;

class CustomAuditWrapper
{
    protected CustomAudit $customAudit;

    protected array $findings = [];

    public function __construct(CustomAudit $customAudit)
    {
        $this->customAudit = $customAudit;
    }

    public function getName(): string
    {
        return $this->customAudit->getName();
    }

    public function run(): bool
    {
        $success = $this->customAudit->audit();

        if (!$success) {
            $this->findings = $this->customAudit->getFindings();
        }

        return $success;
    }

    /**
     * @return array<array<string, mixed>>
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    public function shouldRun(): bool
    {
        return $this->customAudit->shouldRun();
    }
}
