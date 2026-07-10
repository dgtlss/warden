<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\ValueObjects;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use PHPUnit\Framework\TestCase;

final class AuditReportTest extends TestCase
{
    public function testFingerprintAndFindingOrderAreDeterministic(): void
    {
        $finding = $this->finding('rule.low', Severity::Low);
        $critical = $this->finding('rule.critical', Severity::Critical);
        $auditReport = new AuditReport(
            new AuditContext(),
            [AuditResult::complete('test', [$finding, $critical])],
            scannedAt: CarbonImmutable::parse('2026-01-01T00:00:00Z'),
        );

        self::assertSame('rule.critical', $auditReport->findings()[0]->id);
        self::assertSame($finding->fingerprint(), $this->finding('rule.low', Severity::Low)->fingerprint());
    }

    public function testExitCodesDistinguishFindingsErrorsAndThresholds(): void
    {
        $report = new AuditReport(
            new AuditContext(),
            [AuditResult::complete('test', [$this->finding('rule.medium', Severity::Medium)])],
        );

        self::assertSame(1, $report->exitCode('low'));
        self::assertSame(0, $report->exitCode('high'));
        self::assertSame(0, $report->exitCode('never'));

        $failed = new AuditReport(new AuditContext(), [AuditResult::failed('test', 'failed', 'No result')]);
        self::assertSame(2, $failed->exitCode('never'));
    }

    public function testNonBlockingFindingNeverFailsTheGate(): void
    {
        $finding = new Finding('warning', 'test', 'Warning', Severity::Critical, 'Description', blocking: false);
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::complete('test', [$finding])]);

        self::assertSame(0, $auditReport->exitCode('low'));
    }

    private function finding(string $id, Severity $severity): Finding
    {
        return new Finding($id, 'test', 'Finding', $severity, 'Description', package: 'vendor/package', path: 'composer.lock');
    }
}
