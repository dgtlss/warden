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
use Illuminate\Support\Facades\Http;
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

    public function testFindingOnlyFlagSkipsCleanReports(): void
    {
        $this->configureSlack();
        $this->bindReport(new AuditReport(new AuditContext(), [AuditResult::complete('test')]));

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json', '--notify-on-finding' => true]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('"total": 0', Artisan::output());
        Http::assertNothingSent();
    }

    public function testFindingOnlyFlagEnablesNotificationsForAdvisoryFindings(): void
    {
        $this->configureSlack();
        $finding = new Finding('test.advisory', 'test', 'Review issue', Severity::Medium, 'Description', blocking: false);
        $this->bindReport(new AuditReport(new AuditContext(), [AuditResult::complete('test', [$finding])]));

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json', '--notify-on-finding' => true]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('"id": "test.advisory"', Artisan::output());
        Http::assertSentCount(1);
    }

    public function testNotifyStillSendsCleanReportsByDefault(): void
    {
        $this->configureSlack();
        $this->bindReport(new AuditReport(new AuditContext(), [AuditResult::complete('test')]));

        self::assertSame(0, Artisan::call('warden:audit', ['--format' => 'json', '--notify' => true]));
        Http::assertSentCount(1);
    }

    public function testFindingOnlyConfigurationFiltersNotify(): void
    {
        $this->configureSlack();
        config(['warden.notifications.only_on_findings' => true]);
        $this->bindReport(new AuditReport(new AuditContext(), [AuditResult::complete('test')]));

        self::assertSame(0, Artisan::call('warden:audit', ['--format' => 'json', '--notify' => true]));
        Http::assertNothingSent();
    }

    public function testFindingOnlyConfigurationDoesNotEnableNotifications(): void
    {
        $this->configureSlack();
        config(['warden.notifications.only_on_findings' => true]);
        $finding = new Finding('test.high', 'test', 'High issue', Severity::High, 'Description');
        $this->bindReport(new AuditReport(new AuditContext(), [AuditResult::complete('test', [$finding])]));

        self::assertSame(1, Artisan::call('warden:audit', ['--format' => 'json']));
        Http::assertNothingSent();
    }

    public function testSuppressedFindingsDoNotTriggerNotifications(): void
    {
        $this->configureSlack();
        $finding = new Finding('test.high', 'test', 'High issue', Severity::High, 'Description');
        $this->bindReport(new AuditReport(new AuditContext(), [AuditResult::complete('test', [$finding])]));
        config(['warden.ignore_findings' => [[
            'id' => 'test.high',
            'reason' => 'Accepted after review in SEC-123',
            'expires_at' => '2099-12-31',
        ]]]);

        self::assertSame(0, Artisan::call('warden:audit', ['--format' => 'json', '--notify' => true, '--notify-on-finding' => true]));
        self::assertStringContainsString('"ignored": 1', Artisan::output());
        Http::assertNothingSent();
    }

    public function testNotificationFilterDoesNotMaskAuditFailures(): void
    {
        $this->configureSlack();
        $this->bindReport(new AuditReport(new AuditContext(), [AuditResult::failed('composer', 'scanner_failed', 'Registry offline')]));

        $exitCode = Artisan::call('warden:audit', ['--format' => 'json', '--fail-on' => 'never', '--notify-on-finding' => true]);

        self::assertSame(2, $exitCode);
        self::assertStringContainsString('"code": "scanner_failed"', Artisan::output());
        Http::assertNothingSent();
    }

    private function configureSlack(): void
    {
        Http::fake();
        config([
            'warden.notifications.slack.webhook_url' => 'https://example.com/slack',
            'warden.notifications.discord.webhook_url' => null,
            'warden.notifications.teams.webhook_url' => null,
            'warden.notifications.email.recipients' => null,
        ]);
    }

    private function bindReport(AuditReport $auditReport): void
    {
        $this->mock(AuditRunner::class, function (MockInterface $mock) use ($auditReport): void {
            $mock->shouldReceive('run')->once()->andReturn($auditReport);
        });
    }
}
