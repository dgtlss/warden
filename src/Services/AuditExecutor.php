<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Illuminate\Support\Collection;
use Symfony\Component\Process\Process;

class AuditExecutor
{
    protected array $audits = [];

    protected array $results = [];

    public function addAudit(AuditDefinition $auditDefinition): void
    {
        $this->audits[$auditDefinition->id] = $auditDefinition;
    }

    public function reset(): void
    {
        $this->audits = [];
        $this->results = [];
    }

    /**
     * @return array<string, AuditDefinition> Registered audit services keyed by id.
     */
    public function getAudits(): array
    {
        return $this->audits;
    }

    /**
     * Execute all registered audits.
     *
     * @param callable|null $onProgress Called with (string $name, string $status, ?float $durationMs) per audit
     * @return array<string, array{audit_id: string, audit_name: string, success: bool, findings: array, metadata: array<string, mixed>, duration_ms: float}>
     */
    public function execute(string $profile = 'legacy', ?callable $onProgress = null): array
    {
        if ($this->audits === []) {
            return [];
        }

        if ($this->canExecuteInParallel()) {
            return $this->executeInParallel($profile, $onProgress);
        }

        return $this->executeSequentially($onProgress);
    }

    /**
     * @param callable|null $onProgress
     * @return array<string, array{audit_id: string, audit_name: string, success: bool, findings: array, metadata: array<string, mixed>, duration_ms: float}>
     */
    protected function executeSequentially(?callable $onProgress = null): array
    {
        $results = [];

        foreach ($this->audits as $auditId => $definition) {
            $auditService = $definition->make();

            if ($onProgress !== null) {
                $onProgress($definition->name, 'running', null);
            }

            $start = microtime(true);
            $success = $auditService->run();
            $durationMs = round((microtime(true) - $start) * 1000, 1);

            $results[$auditId] = [
                'audit_id' => $auditId,
                'audit_name' => $definition->name,
                'success' => $success,
                'findings' => $auditService->getFindings(),
                'metadata' => method_exists($auditService, 'getMetadata') ? $auditService->getMetadata() : [],
                'duration_ms' => $durationMs,
            ];

            if ($onProgress !== null) {
                $status = $success ? 'done' : 'failed';
                $onProgress($definition->name, $status, $durationMs);
            }
        }

        $this->results = $results;

        return $results;
    }

    /**
     * @param callable|null $onProgress
     * @return array<string, array{audit_id: string, audit_name: string, success: bool, findings: array, metadata: array<string, mixed>, duration_ms: float}>
     */
    protected function executeInParallel(string $profile, ?callable $onProgress = null): array
    {
        $artisan = base_path('artisan');
        if (!file_exists($artisan)) {
            return $this->executeSequentially($onProgress);
        }

        $queue = array_values($this->audits);
        $running = [];
        $results = [];
        $maxConcurrency = max(1, (int) config('warden.audits.max_concurrency', 4));

        while ($queue !== [] || $running !== []) {
            while ($queue !== [] && count($running) < $maxConcurrency) {
                /** @var AuditDefinition $definition */
                $definition = array_shift($queue);

                if ($onProgress !== null) {
                    $onProgress($definition->name, 'running', null);
                }

                $process = new Process([
                    PHP_BINARY,
                    $artisan,
                    'warden:audit:worker',
                    $definition->id,
                    '--profile=' . $profile,
                    '--no-ansi',
                ], base_path());

                $process->setTimeout((int) config('warden.audits.timeout', 300));
                $process->start();

                $running[$definition->id] = [
                    'definition' => $definition,
                    'process' => $process,
                    'started_at' => microtime(true),
                ];
            }

            foreach ($running as $auditId => $entry) {
                /** @var Process $process */
                $process = $entry['process'];
                if ($process->isRunning()) {
                    continue;
                }

                /** @var AuditDefinition $definition */
                $definition = $entry['definition'];
                $durationMs = round((microtime(true) - $entry['started_at']) * 1000, 1);
                $decoded = json_decode((string) $process->getOutput(), true);

                if (!is_array($decoded)) {
                    $decoded = [
                        'audit_id' => $auditId,
                        'audit_name' => $definition->name,
                        'success' => false,
                        'findings' => [[
                            'package' => $definition->name,
                            'title' => 'Audit worker failed to produce valid JSON output',
                            'rule_id' => 'warden.worker.invalid-output',
                            'category' => 'execution',
                            'severity' => 'high',
                            'description' => trim($process->getErrorOutput()) !== '' ? trim($process->getErrorOutput()) : 'Unknown worker failure.',
                            'error' => trim($process->getErrorOutput()),
                        ]],
                        'metadata' => [],
                    ];
                }

                $decoded['duration_ms'] = $durationMs;
                $results[$auditId] = $decoded;

                if ($onProgress !== null) {
                    $onProgress($definition->name, !empty($decoded['success']) ? 'done' : 'failed', $durationMs);
                }

                unset($running[$auditId]);
            }

            usleep(10_000);
        }

        $this->results = $results;

        return $results;
    }

    protected function canExecuteInParallel(): bool
    {
        return (bool) config('warden.audits.parallel_execution', true);
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
