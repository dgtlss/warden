<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Carbon\Carbon;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\AuditHistoryService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\DB;

class AuditHistoryServiceTest extends TestCase
{
    private AuditHistoryService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../../src/database/migrations');
        $this->service = new AuditHistoryService();
    }

    public function testStoreReturnsInsertedIdAndPersistsRecord(): void
    {
        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Critical vulnerability',
                severity: Severity::CRITICAL,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
        ];

        $id = $this->service->store('composer', $findings, ['trigger' => 'manual'], 123);

        $this->assertIsInt($id);
        $record = DB::table('warden_audit_history')->find($id);

        $this->assertNotNull($record);
        $this->assertEquals('composer', $record->audit_type);
        $this->assertEquals(1, $record->total_findings);
        $this->assertEquals(1, $record->critical_findings);
    }

    public function testVerifyReturnsTrueForValidRecord(): void
    {
        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High vulnerability',
                severity: Severity::HIGH,
                affectedVersions: '<1.0',
            ),
        ];

        $id = $this->service->store('composer', $findings);

        $this->assertTrue($this->service->verify($id));
    }

    public function testVerifyReturnsFalseWhenRecordMissing(): void
    {
        $this->assertFalse($this->service->verify(9999));
    }

    public function testVerifyAllReturnsSummary(): void
    {
        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High vulnerability',
                severity: Severity::HIGH,
                affectedVersions: '<1.0',
            ),
        ];

        $this->service->store('composer', $findings);
        $results = $this->service->verifyAll();

        $this->assertEquals(1, $results['verified']);
        $this->assertEquals(0, $results['failed']);
    }

    public function testGetTrendsReturnsRecentRecords(): void
    {
        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Low vulnerability',
                severity: Severity::LOW,
                affectedVersions: '<1.0',
            ),
        ];

        $this->service->store('composer', $findings);
        $trends = $this->service->getTrends(30);

        $this->assertNotEmpty($trends);
        $this->assertEquals('composer', $trends[0]['audit_type']);
    }

    public function testGetLatestReturnsStoredRecord(): void
    {
        $findings = [
            new Finding(
                source: 'npm',
                package: 'test/npm',
                title: 'Medium vulnerability',
                severity: Severity::MEDIUM,
                affectedVersions: '<2.0',
            ),
        ];

        $this->service->store('npm', $findings, [], 0, 'schedule');
        $latest = $this->service->getLatest('npm');

        $this->assertNotNull($latest);
        $this->assertEquals('npm', $latest['audit_type']);
        $this->assertEquals('schedule', $latest['trigger']);
        $this->assertEquals(1, $latest['total_findings']);
        $this->assertIsArray($latest['findings']);
    }

    public function testGetStatisticsReturnsAggregateCounts(): void
    {
        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Critical vulnerability',
                severity: Severity::CRITICAL,
                affectedVersions: '<1.0',
            ),
        ];

        $this->service->store('composer', $findings, [], 200);
        $stats = $this->service->getStatistics(30);

        $this->assertEquals(1, $stats['total_audits']);
        $this->assertEquals(1, $stats['total_findings']);
        $this->assertEquals(1, $stats['total_critical']);
    }

    public function testClearOldHistoryRemovesRecords(): void
    {
        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High vulnerability',
                severity: Severity::HIGH,
                affectedVersions: '<1.0',
            ),
        ];

        $id = $this->service->store('composer', $findings);
        DB::table('warden_audit_history')
            ->where('id', $id)
            ->update([
                'created_at' => Carbon::now()->subDays(120),
                'updated_at' => Carbon::now()->subDays(120),
            ]);

        $deleted = $this->service->clearOldHistory(90);

        $this->assertEquals(1, $deleted);
    }
}
