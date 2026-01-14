<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/**
 * Service for managing audit history and trends.
 */
class AuditHistoryService
{
    protected string $tableName;

    public function __construct()
    {
        $table = Config::get('warden.history.table', 'warden_audit_history');
        $this->tableName = is_string($table) ? $table : 'warden_audit_history';
    }

    /**
     * Store an audit result in history.
     *
     * @param string $auditType
     * @param array<int, Finding> $findings
     * @param array<string, mixed> $metadata
     * @param int $durationMs
     * @param string $trigger
     * @param string|null $triggeredBy
     */
    public function store(
        string $auditType,
        array $findings,
        array $metadata = [],
        int $durationMs = 0,
        string $trigger = 'manual',
        ?string $triggeredBy = null
    ): int {
        $severityBreakdown = $this->calculateSeverityBreakdown($findings);
        $findingsJson = json_encode($this->findingsToArray($findings));
        $metadataJson = json_encode($metadata);

        $data = [
            'audit_type' => $auditType,
            'total_findings' => count($findings),
            'critical_findings' => $severityBreakdown['critical'],
            'high_findings' => $severityBreakdown['high'],
            'medium_findings' => $severityBreakdown['medium'],
            'low_findings' => $severityBreakdown['low'],
            'findings' => $findingsJson,
            'metadata' => $metadataJson,
            'has_failures' => count($findings) > 0,
            'trigger' => $trigger,
            'triggered_by' => $triggeredBy,
            'duration_ms' => $durationMs,
            'created_at' => now(),
            'updated_at' => now(),
        ];

        $data['integrity_hash'] = $this->calculateHash($data);

        $id = DB::table($this->tableName)->insertGetId($data);

        return $id;
    }

    /**
     * Calculate integrity hash for audit data.
     *
     * @param array<string, mixed> $data
     */
    public function calculateHash(array $data): string
    {
        $hashableData = [
            'audit_type' => $data['audit_type'] ?? '',
            'total_findings' => $data['total_findings'] ?? 0,
            'critical_findings' => $data['critical_findings'] ?? 0,
            'high_findings' => $data['high_findings'] ?? 0,
            'medium_findings' => $data['medium_findings'] ?? 0,
            'low_findings' => $data['low_findings'] ?? 0,
            'findings' => $data['findings'] ?? '[]',
            'metadata' => $data['metadata'] ?? '{}',
        ];

        /** @var string $secret */
        $secret = Config::get('warden.security.history_secret', Config::get('app.key', 'warden-default-key'));

        return hash_hmac('sha256', json_encode($hashableData) ?: '', $secret);
    }

    /**
     * Verify the integrity of an audit record.
     */
    public function verify(int $id): bool
    {
        $record = DB::table($this->tableName)->find($id);

        if ($record === null) {
            return false;
        }

        $storedHash = $record->integrity_hash ?? null;

        if ($storedHash === null || !is_string($storedHash)) {
            return false;
        }

        $data = [
            'audit_type' => $record->audit_type ?? '',
            'total_findings' => $record->total_findings ?? 0,
            'critical_findings' => $record->critical_findings ?? 0,
            'high_findings' => $record->high_findings ?? 0,
            'medium_findings' => $record->medium_findings ?? 0,
            'low_findings' => $record->low_findings ?? 0,
            'findings' => $record->findings ?? '[]',
            'metadata' => $record->metadata ?? '{}',
        ];

        $calculatedHash = $this->calculateHash($data);

        return hash_equals($calculatedHash, $storedHash);
    }

    /**
     * Verify all audit records in the database.
     *
     * @return array{verified: int, failed: int, missing_hash: int, failed_ids: array<int, int>}
     */
    public function verifyAll(): array
    {
        $results = [
            'verified' => 0,
            'failed' => 0,
            'missing_hash' => 0,
            'failed_ids' => [],
        ];

        $records = DB::table($this->tableName)->get();

        foreach ($records as $record) {
            $recordId = $record->id ?? 0;
            $id = is_numeric($recordId) ? (int) $recordId : 0;
            $storedHash = $record->integrity_hash ?? null;

            if ($storedHash === null || !is_string($storedHash) || $storedHash === '') {
                $results['missing_hash']++;
                continue;
            }

            if ($this->verify($id)) {
                $results['verified']++;
            } else {
                $results['failed']++;
                $results['failed_ids'][] = $id;
            }
        }

        return $results;
    }

    /**
     * Get audit trends over a period.
     *
     * @param int $days
     * @return array<int, array<string, mixed>>
     */
    public function getTrends(int $days = 30): array
    {
        $startDate = now()->subDays($days);

        $results = DB::table($this->tableName)
            ->where('created_at', '>=', $startDate)
            ->orderBy('created_at', 'asc')
            ->get();

        return $results->map(function ($record) {
            return [
                'id' => $record->id ?? 0,
                'audit_type' => $record->audit_type ?? '',
                'total_findings' => $record->total_findings ?? 0,
                'critical_findings' => $record->critical_findings ?? 0,
                'high_findings' => $record->high_findings ?? 0,
                'medium_findings' => $record->medium_findings ?? 0,
                'low_findings' => $record->low_findings ?? 0,
                'has_failures' => $record->has_failures ?? false,
                'duration_ms' => $record->duration_ms ?? 0,
                'created_at' => $record->created_at ?? null,
            ];
        })->all();
    }

    /**
     * Get the latest audit result.
     *
     * @param string|null $auditType
     * @return array<string, mixed>|null
     */
    public function getLatest(?string $auditType = null): ?array
    {
        $query = DB::table($this->tableName);

        if ($auditType !== null) {
            $query->where('audit_type', $auditType);
        }

        $record = $query->orderBy('created_at', 'desc')->first();

        if ($record === null) {
            return null;
        }

        return [
            'id' => $record->id ?? 0,
            'audit_type' => $record->audit_type ?? '',
            'total_findings' => $record->total_findings ?? 0,
            'critical_findings' => $record->critical_findings ?? 0,
            'high_findings' => $record->high_findings ?? 0,
            'medium_findings' => $record->medium_findings ?? 0,
            'low_findings' => $record->low_findings ?? 0,
            'findings' => $this->parseFindings(is_string($record->findings ?? null) ? $record->findings : '[]'),
            'metadata' => json_decode(is_string($record->metadata ?? null) ? $record->metadata : '{}', true),
            'has_failures' => $record->has_failures ?? false,
            'trigger' => $record->trigger ?? 'manual',
            'triggered_by' => $record->triggered_by ?? null,
            'duration_ms' => $record->duration_ms ?? 0,
            'created_at' => $record->created_at ?? null,
        ];
    }

    /**
     * Get audit statistics.
     *
     * @param int $days
     * @return array<string, mixed>
     */
    public function getStatistics(int $days = 30): array
    {
        $startDate = now()->subDays($days);

        $stats = DB::table($this->tableName)
            ->where('created_at', '>=', $startDate)
            ->selectRaw('
                COUNT(*) as total_audits,
                SUM(total_findings) as total_findings,
                SUM(critical_findings) as total_critical,
                SUM(high_findings) as total_high,
                SUM(medium_findings) as total_medium,
                SUM(low_findings) as total_low,
                AVG(duration_ms) as avg_duration_ms,
                AVG(total_findings) as avg_findings_per_audit
            ')
            ->first();

        if ($stats === null) {
            return [
                'total_audits' => 0,
                'total_findings' => 0,
                'total_critical' => 0,
                'total_high' => 0,
                'total_medium' => 0,
                'total_low' => 0,
                'avg_duration_ms' => 0,
                'avg_findings_per_audit' => 0,
            ];
        }

        return [
            'total_audits' => is_numeric($stats->total_audits ?? null) ? (int) $stats->total_audits : 0,
            'total_findings' => is_numeric($stats->total_findings ?? null) ? (int) $stats->total_findings : 0,
            'total_critical' => is_numeric($stats->total_critical ?? null) ? (int) $stats->total_critical : 0,
            'total_high' => is_numeric($stats->total_high ?? null) ? (int) $stats->total_high : 0,
            'total_medium' => is_numeric($stats->total_medium ?? null) ? (int) $stats->total_medium : 0,
            'total_low' => is_numeric($stats->total_low ?? null) ? (int) $stats->total_low : 0,
            'avg_duration_ms' => is_numeric($stats->avg_duration_ms ?? null) ? (float) $stats->avg_duration_ms : 0.0,
            'avg_findings_per_audit' => is_numeric($stats->avg_findings_per_audit ?? null) ? (float) $stats->avg_findings_per_audit : 0.0,
        ];
    }

    /**
     * Clear old audit history.
     *
     * @param int $daysToKeep
     * @return int Number of records deleted
     */
    public function clearOldHistory(int $daysToKeep = 90): int
    {
        $cutoffDate = now()->subDays($daysToKeep);

        return DB::table($this->tableName)
            ->where('created_at', '<', $cutoffDate)
            ->delete();
    }

    /**
     * Calculate severity breakdown from findings.
     *
     * @param array<int, Finding> $findings
     * @return array<string, int>
     */
    protected function calculateSeverityBreakdown(array $findings): array
    {
        $breakdown = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
        ];

        foreach ($findings as $finding) {
            $severity = strtolower($finding->severity->value);

            if ($severity === 'moderate') {
                $severity = 'medium';
            }

            if (isset($breakdown[$severity])) {
                $breakdown[$severity]++;
            }
        }

        return $breakdown;
    }

    /**
     * Convert findings to array format for storage.
     *
     * @param array<int, Finding> $findings
     * @return array<int, array<string, mixed>>
     */
    protected function findingsToArray(array $findings): array
    {
        return array_map(fn(Finding $f) => $f->toArray(), $findings);
    }

    /**
     * Parse findings JSON from database.
     *
     * @param string $json
     * @return array<int, array<string, mixed>>
     */
    protected function parseFindings(string $json): array
    {
        $decoded = json_decode($json, true);

        if (!is_array($decoded)) {
            return [];
        }

        // Ensure all elements are arrays with mixed values
        /** @var array<int, array<string, mixed>> $filtered */
        $filtered = [];
        foreach ($decoded as $item) {
            if (is_array($item)) {
                /** @var array<string, mixed> $item */
                $filtered[] = $item;
            }
        }

        return $filtered;
    }
}
