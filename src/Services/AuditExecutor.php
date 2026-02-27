<?php

namespace Dgtlss\Warden\Services;

use Illuminate\Support\Collection;
use Symfony\Component\Process\Process;
use function Laravel\Prompts\spin;

class AuditExecutor
{
    protected array $audits = [];

    protected array $results = [];

    public function addAudit(object $auditService): void
    {
        $this->audits[$auditService->getName()] = $auditService;
    }

    /**
     * Execute all registered audits.
     *
     * @return array<string, array{success: bool, findings: array, service: object}>
     */
    public function execute(bool $showProgress = true): array
    {
        if ($this->audits === []) {
            return [];
        }

        if ($showProgress) {
            return spin(
                fn() => $this->runAll(),
                'Running security audits...'
            );
        }

        return $this->runAll();
    }

    protected function runAll(): array
    {
        $results = [];

        foreach ($this->audits as $name => $auditService) {
            $success = $auditService->run();
            $results[$name] = [
                'success' => $success,
                'findings' => $auditService->getFindings(),
                'service' => $auditService,
            ];
        }

        return $results;
    }

    public function getAllFindings(): Collection
    {
        return collect($this->results)
            ->filter(fn($result) => !empty($result['findings']))
            ->pluck('findings')
            ->flatten(1);
    }

    public function hasFailures(): bool
    {
        return collect($this->results)
            ->contains(fn($result) => !$result['success']);
    }

    public function getFailedAudits(): Collection
    {
        return collect($this->results)
            ->filter(fn($result) => !$result['success'])
            ->keys();
    }
}
