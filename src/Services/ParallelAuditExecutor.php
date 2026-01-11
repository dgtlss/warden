<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\AuditService;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Collection;
use Symfony\Component\Process\Process;
use function Laravel\Prompts\spin;

class ParallelAuditExecutor
{
    /**
     * @var array<string, AuditService>
     */
    protected array $processes = [];

    /**
     * @var array<string, array{success: bool, findings: array<int, Finding>, service: AuditService}>
     */
    protected array $results = [];

    /**
     * Add an audit service to be executed in parallel.
     */
    public function addAudit(AuditService $auditService): void
    {
        $this->processes[$auditService->getName()] = $auditService;
    }

    /**
     * Execute all audits in parallel.
     *
     * @return array<string, array{success: bool, findings: array<int, Finding>, service: AuditService}>
     */
    public function execute(bool $showProgress = true): array
    {
        if ($this->processes === []) {
            return [];
        }

        if ($showProgress) {
            /** @var array<string, array{success: bool, findings: array<int, Finding>, service: AuditService}> $results */
            $results = spin(
                fn() => $this->runParallel(),
                'Running security audits in parallel...'
            );
            $this->results = $results;
            return $results;
        }

        $this->results = $this->runParallel();
        return $this->results;
    }

    /**
     * Run audits in parallel using concurrent processing.
     *
     * @return array<string, array{success: bool, findings: array<int, Finding>, service: AuditService}>
     */
    protected function runParallel(): array
    {
        /** @var array<string, array{success: bool, findings: array<int, Finding>, service: AuditService}> $results */
        $results = [];
        $runningProcesses = [];

        // Start all processes
        foreach ($this->processes as $name => $auditService) {
            // For services that implement async execution
            if (method_exists($auditService, 'runAsync')) {
                $runningProcesses[$name] = $auditService->runAsync();
            } else {
                // Run synchronously but collect results
                $success = $auditService->run();
                $results[$name] = [
                    'success' => $success,
                    'findings' => $auditService->getFindings(),
                    'service' => $auditService
                ];
            }
        }

        // Wait for async processes to complete
        foreach ($runningProcesses as $name => $process) {
            if ($process instanceof Process) {
                $process->wait();
                $success = $process->isSuccessful();
            } elseif (is_object($process) && method_exists($process, 'wait')) {
                // Handle other async implementations
                $process->wait();
                $success = method_exists($process, 'isSuccessful') ? $process->isSuccessful() : true;
            } else {
                $success = (bool) $process;
            }

            $results[$name] = [
                'success' => (bool) $success,
                'findings' => $this->processes[$name]->getFindings(),
                'service' => $this->processes[$name]
            ];
        }

        return $results;
    }

    /**
     * Get all findings from executed audits.
     *
     * @return Collection<int, Finding>
     */
    public function getAllFindings(): Collection
    {
        /** @var Collection<int, Finding> $collection */
        $collection = collect($this->results)
            ->filter(fn(array $result) => !empty($result['findings']))
            ->pluck('findings')
            ->flatten(1);
            
        return $collection;
    }

    /**
     * Check if any audit failed.
     */
    public function hasFailures(): bool
    {
        return collect($this->results)
            ->contains(fn(array $result) => !$result['success']);
    }

    /**
     * Get failed audits.
     *
     * @return Collection<int, string>
     */
    public function getFailedAudits(): Collection
    {
        /** @var Collection<int, string> $collection */
        $collection = collect($this->results)
            ->filter(fn(array $result) => !$result['success'])
            ->keys();
            
        return $collection;
    }
} 