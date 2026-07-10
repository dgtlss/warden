<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Commands;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\AuditRunner;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Artisan;
use Mockery\MockInterface;

final class WardenAuditCommandTest extends TestCase
{
    public function testJsonReportAndFindingExitCodeAreDeterministic(): void
    {
        $finding = new Finding('test.high', 'test', 'High issue', Severity::High, 'Description', path: 'composer.lock');
        $this->bindReport(new AuditReport(
            new AuditContext(),
            [AuditResult::complete('test', [$finding])],
            scannedAt: CarbonImmutable::parse('2026-01-01T00:00:00Z'),
        ));

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json']);
        $output = Artisan::output();

        self::assertStringContainsString('"schema_version": "2.0.0"', $output);
        self::assertStringContainsString('"id": "test.high"', $output);
        self::assertSame(1, $exitCode);
    }

    public function testFailOnChangesOnlyTheGateNotTheReport(): void
    {
        $finding = new Finding('test.medium', 'test', 'Medium issue', Severity::Medium, 'Description');
        $this->bindReport(new AuditReport(new AuditContext(), [AuditResult::complete('test', [$finding])]));

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json', '--fail-on' => 'high']);

        self::assertStringContainsString('"id": "test.medium"', Artisan::output());
        self::assertSame(0, $exitCode);
    }

    public function testAuditFailureIsMachineReadableAndExitsTwo(): void
    {
        $this->bindReport(new AuditReport(
            new AuditContext(),
            [AuditResult::failed('composer', 'scanner_failed', 'Registry offline')],
        ));

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json', '--fail-on' => 'never']);
        $output = Artisan::output();

        self::assertStringContainsString('"status": "failed"', $output);
        self::assertStringContainsString('"code": "scanner_failed"', $output);
        self::assertSame(2, $exitCode);
    }

    public function testInvalidMachineOptionReturnsStructuredErrorBeforeAuditsRun(): void
    {
        $this->mock(AuditRunner::class, function (MockInterface $mock): void {
            $mock->shouldNotReceive('run');
        });

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json', '--profile' => 'invalid']);

        self::assertStringContainsString('"code": "invalid_option"', Artisan::output());
        self::assertSame(2, $exitCode);
    }

    public function testUnknownAuditIsRejectedBeforeExecution(): void
    {
        $this->mock(AuditRunner::class, function (MockInterface $mock): void {
            $mock->shouldReceive('availableAuditIds')->once()->andReturn(['composer']);
            $mock->shouldNotReceive('run');
        });

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json', '--only' => 'unknown']);

        self::assertStringContainsString('Unknown audit', Artisan::output());
        self::assertSame(2, $exitCode);
    }

    public function testInvalidSuppressionIsRejectedBeforeExecution(): void
    {
        config(['warden.ignore_findings' => [['id' => 'missing-review-metadata']]]);
        $this->mock(AuditRunner::class, function (MockInterface $mock): void {
            $mock->shouldNotReceive('run');
        });

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json']);

        self::assertStringContainsString('"code": "suppression_invalid"', Artisan::output());
        self::assertSame(2, $exitCode);
    }

    public function testInvalidRuleOverrideIsAConfigurationErrorBeforeScanning(): void
    {
        config(['warden.rule_overrides' => ['unknown.rule' => 'off']]);

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json', '--only' => 'source']);

        self::assertSame(2, $exitCode);
        self::assertStringContainsString('"code": "unknown_rule"', Artisan::output());
    }

    private function bindReport(AuditReport $auditReport): void
    {
        $this->mock(AuditRunner::class, function (MockInterface $mock) use ($auditReport): void {
            $mock->shouldReceive('run')->once()->andReturn($auditReport);
        });
    }
}
