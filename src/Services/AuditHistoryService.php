<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Data\AuditRunReport;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class AuditHistoryService
{
    public function isEnabled(): bool
    {
        return (bool) config('warden.history.enabled', false);
    }

    public function table(): string
    {
        return (string) config('warden.history.table', 'warden_audit_history');
    }

    public function canPersist(): bool
    {
        if (!$this->isEnabled()) {
            return false;
        }

        try {
            return Schema::hasTable($this->table());
        } catch (\Throwable) {
            return false;
        }
    }

    public function store(AuditRunReport $report, array $context = []): void
    {
        if (!$this->canPersist()) {
            return;
        }

        $severityCounts = $report->severityCounts();

        DB::table($this->table())->insert([
            'audit_type' => 'full',
            'total_findings' => $report->totalFindings(),
            'critical_findings' => $severityCounts['critical'],
            'high_findings' => $severityCounts['high'],
            'medium_findings' => $severityCounts['medium'],
            'low_findings' => $severityCounts['low'],
            'findings' => json_encode($report->findings, JSON_UNESCAPED_SLASHES),
            'metadata' => json_encode([
                'profile' => $report->profile,
                'suppressed_count' => count($report->suppressedFindings),
                'abandoned_packages' => $report->abandonedPackages,
                'results' => array_map(static fn ($result): array => [
                    'audit_id' => $result->auditId,
                    'audit_name' => $result->auditName,
                    'success' => $result->success,
                    'duration_ms' => $result->durationMs,
                    'cached' => $result->cached,
                    'metadata' => $result->metadata,
                ], $report->results),
                'context' => $context,
            ], JSON_UNESCAPED_SLASHES),
            'has_failures' => $report->hasFailures,
            'trigger' => (string) ($context['trigger'] ?? 'manual'),
            'triggered_by' => isset($context['triggered_by']) ? (string) $context['triggered_by'] : null,
            'duration_ms' => (int) round($report->durationMs),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function latest(int $limit = 10): array
    {
        if (!$this->canPersist()) {
            return [];
        }

        return DB::table($this->table())
            ->orderByDesc('created_at')
            ->limit($limit)
            ->get()
            ->map(static function ($row): array {
                return [
                    'id' => $row->id,
                    'audit_type' => $row->audit_type,
                    'total_findings' => $row->total_findings,
                    'critical_findings' => $row->critical_findings,
                    'high_findings' => $row->high_findings,
                    'medium_findings' => $row->medium_findings,
                    'low_findings' => $row->low_findings,
                    'has_failures' => (bool) $row->has_failures,
                    'trigger' => $row->trigger,
                    'triggered_by' => $row->triggered_by,
                    'duration_ms' => $row->duration_ms,
                    'created_at' => (string) $row->created_at,
                    'metadata' => is_string($row->metadata) ? json_decode($row->metadata, true) : null,
                ];
            })
            ->all();
    }

    public function prune(?int $retentionDays = null): int
    {
        if (!$this->canPersist()) {
            return 0;
        }

        $days = $retentionDays ?? (int) config('warden.history.retention_days', 90);

        return DB::table($this->table())
            ->where('created_at', '<', now()->subDays($days))
            ->delete();
    }

    /**
     * @param array<string, mixed> $attempt
     */
    public function appendResolutionAttemptToLatest(array $attempt): void
    {
        if (!$this->canPersist()) {
            return;
        }

        $latest = DB::table($this->table())
            ->orderByDesc('created_at')
            ->first();

        if ($latest === null) {
            return;
        }

        $metadata = is_string($latest->metadata)
            ? json_decode($latest->metadata, true)
            : [];

        if (!is_array($metadata)) {
            $metadata = [];
        }

        $resolutionAttempts = isset($metadata['resolution_attempts']) && is_array($metadata['resolution_attempts'])
            ? $metadata['resolution_attempts']
            : [];

        $resolutionAttempts[] = $attempt;
        $metadata['resolution_attempts'] = $resolutionAttempts;

        DB::table($this->table())
            ->where('id', $latest->id)
            ->update([
                'metadata' => json_encode($metadata, JSON_UNESCAPED_SLASHES),
                'updated_at' => now(),
            ]);
    }
}
