<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Illuminate\Support\Collection;

class AuditExecutor
{
    protected array $audits = [];

    protected array $results = [];

    public function addAudit(AuditServiceInterface $auditService): void
    {
        $this->audits[$auditService->getName()] = $auditService;
    }

    /**
     * @return array<string, AuditServiceInterface> Registered audit services keyed by name.
     */
    public function getAudits(): array
    {
        return $this->audits;
    }

    /**
     * Execute all registered audits.
     *
     * @param callable|null $onProgress Called with (string $name, string $status, ?float $durationMs) per audit
     * @return array<string, array{success: bool, findings: array, service: AuditServiceInterface}>
     */
    public function execute(?callable $onProgress = null): array
    {
        if ($this->audits === []) {
            return [];
        }

        $results = [];

        foreach ($this->audits as $name => $auditService) {
            if ($onProgress !== null) {
                $onProgress($name, 'running', null);
            }

            $start = microtime(true);
            $success = $auditService->run();
            $durationMs = round((microtime(true) - $start) * 1000, 1);

            $results[$name] = [
                'success' => $success,
                'findings' => $auditService->getFindings(),
                'service' => $auditService,
            ];

            if ($onProgress !== null) {
                $status = $success ? 'done' : 'failed';
                $onProgress($name, $status, $durationMs);
            }
        }

        $this->results = $results;

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
