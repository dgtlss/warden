<?php

namespace Dgtlss\Warden\Services;

use Illuminate\Support\Collection;
use Symfony\Component\Process\Process;
use function Laravel\Prompts\spin;

class ParallelAuditExecutor
{
    protected array $processes = [];

    protected array $results = [];

    /**
     * Add an audit service to be executed in parallel.
     */
    public function addAudit(object $auditService): void
    {
        $this->processes[$auditService->getName()] = $auditService;
    }

    /**
     * Execute all audits in parallel.
     *
     * @return array Results keyed by audit name
     */
    public function execute(bool $showProgress = true): array
    {
        if ($this->processes === []) {
            return [];
        }

        if ($showProgress) {
            return spin(
                fn() => $this->runParallel(),
                'Running security audits in parallel...'
            );
        }

        return $this->runParallel();
    }

    /**
     * Run audits in parallel using concurrent processing.
     */
    protected function runParallel(): array
    {
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
            } else {
                // Handle other async implementations
                $success = $process->wait();
            }

            $results[$name] = [
                'success' => $success,
                'findings' => $this->processes[$name]->getFindings(),
                'service' => $this->processes[$name]
            ];
        }

        return $results;
    }

    /**
     * Get all findings from executed audits.
     */
    public function getAllFindings(): Collection
    {
        return collect($this->results)
            ->filter(fn($result) => !empty($result['findings']))
            ->pluck('findings')
            ->flatten(1);
    }

    /**
     * Check if any audit failed.
     */
    public function hasFailures(): bool
    {
        return collect($this->results)
            ->contains(fn($result) => !$result['success']);
    }

    /**
     * Get failed audits.
     */
    public function getFailedAudits(): Collection
    {
        return collect($this->results)
            ->filter(fn($result) => !$result['success'])
            ->keys();
    }
} 