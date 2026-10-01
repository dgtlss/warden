<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\NotificationDispatcher;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;

final class NotificationDispatcherTest extends TestCase
{
    public function testConfiguredChannelIsDispatchedExactlyOnce(): void
    {
        Http::fake();
        $this->configureChannels(slack: 'https://example.com/slack');

        self::assertSame([], (new NotificationDispatcher())->send($this->report()));
        Http::assertSentCount(1);
    }

    public function testChannelFailureReturnsANonGatingWarning(): void
    {
        Http::fake(['https://example.com/slack' => Http::response([], 500)]);
        $this->configureChannels(slack: 'https://example.com/slack');

        $warnings = (new NotificationDispatcher())->send($this->report());

        self::assertCount(1, $warnings);
        self::assertStringContainsString('Slack notification failed:', $warnings[0]);
    }

    public function testMultipleConfiguredChannelsEachDispatchOnce(): void
    {
        Http::fake();
        $this->configureChannels(
            slack: 'https://example.com/slack',
            discord: 'https://example.com/discord',
            teams: 'https://example.com/teams',
        );

        self::assertSame([], (new NotificationDispatcher())->send($this->report()));
        Http::assertSentCount(3);
    }

    public function testEmptyFindingReportStillDispatchesWhenRequested(): void
    {
        Http::fake();
        $this->configureChannels(slack: 'https://example.com/slack');
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::complete('test')]);

        self::assertSame([], (new NotificationDispatcher())->send($auditReport));
        Http::assertSentCount(1);
    }

    public function testFindingOnlyConfigurationSkipsEmptyReportsForEveryChannel(): void
    {
        Http::fake();
        Mail::fake();
        $this->configureChannels(
            slack: 'https://example.com/slack',
            discord: 'https://example.com/discord',
            teams: 'https://example.com/teams',
        );
        config([
            'warden.notifications.only_on_findings' => true,
            'warden.notifications.email.recipients' => 'security@example.com',
        ]);
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::complete('test')]);

        self::assertSame([], (new NotificationDispatcher())->send($auditReport));
        Http::assertNothingSent();
        Mail::assertNothingSent();
    }

    public function testFindingOnlyArgumentSkipsEmptyReports(): void
    {
        Http::fake();
        $this->configureChannels(slack: 'https://example.com/slack');
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::complete('test')]);

        self::assertSame([], (new NotificationDispatcher())->send($auditReport, onlyOnFindings: true));
        Http::assertNothingSent();
    }

    public function testFindingOnlyConfigurationStillDispatchesActiveFindings(): void
    {
        Http::fake();
        $this->configureChannels(slack: 'https://example.com/slack');
        config(['warden.notifications.only_on_findings' => true]);

        self::assertSame([], (new NotificationDispatcher())->send($this->report()));
        Http::assertSentCount(1);
    }

    public function testIgnoredFindingsDoNotTriggerFindingOnlyNotifications(): void
    {
        Http::fake();
        $this->configureChannels(slack: 'https://example.com/slack');
        config(['warden.notifications.only_on_findings' => true]);
        $finding = new Finding('test', 'test', 'Finding', Severity::High, 'Description');
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::complete('test')], ignoredFindings: [$finding]);

        self::assertSame([], (new NotificationDispatcher())->send($auditReport));
        Http::assertNothingSent();
    }

    private function report(): AuditReport
    {
        $finding = new Finding('test', 'test', 'Finding', Severity::High, 'Description');

        return new AuditReport(new AuditContext(), [AuditResult::complete('test', [$finding])]);
    }

    private function configureChannels(?string $slack = null, ?string $discord = null, ?string $teams = null): void
    {
        config([
            'warden.notifications.slack.webhook_url' => $slack,
            'warden.notifications.discord.webhook_url' => $discord,
            'warden.notifications.teams.webhook_url' => $teams,
            'warden.notifications.email.recipients' => null,
        ]);
    }
}
