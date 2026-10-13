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

    public function testExplicitErrorOptInNotifiesWithoutAnAllClear(): void
    {
        Http::fake();
        $this->configureChannels(slack: 'https://example.com/slack', discord: 'https://example.com/discord', teams: 'https://example.com/teams');
        config(['warden.notifications.only_on_findings' => true, 'warden.notifications.on_errors' => true]);
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::failed('source', 'unreadable_file', 'Unable to read app/Private.php.')]);
        self::assertSame([], (new NotificationDispatcher())->send($auditReport, onlyOnFindings: true));
        Http::assertSentCount(3);
        foreach (Http::recorded() as [$request]) {
            $body = $request->body();
            self::assertStringContainsString('Incomplete scan', $body);
            self::assertStringContainsString('unreadable_file', $body);
            self::assertStringContainsString('Private.php', $body);
            self::assertStringNotContainsString('All Clear', $body);
            self::assertStringNotContainsString('No Issues Found', $body);
        }
    }

    public function testErrorNotificationsCanBeExplicitlyDisabled(): void
    {
        Http::fake();
        $this->configureChannels(slack: 'https://example.com/slack');
        config(['warden.notifications.on_errors' => false]);
        (new NotificationDispatcher())->send(new AuditReport(new AuditContext(), [AuditResult::failed('source', 'parse_error', 'Fixture error')]));
        Http::assertNothingSent();
    }

    public function testReportMessagesPreserveDispositionLocationAndCompletedState(): void
    {
        $report = new AuditReport(new AuditContext(), [AuditResult::complete('source', [
            new Finding('advisory', 'source', 'Review output', Severity::High, 'Description', path: 'app/Example.php', line: 12, blocking: false),
        ])]);
        $body = \Dgtlss\Warden\Notifications\ReportMessage::body($report);
        self::assertStringContainsString('0 blocking findings, 1 advisory findings', $body);
        self::assertStringContainsString('HIGH advisory', $body);
        self::assertStringContainsString('app/Example.php:12', $body);
        self::assertStringContainsString('Findings detected', \Dgtlss\Warden\Notifications\ReportMessage::title($report));
        $clean = new AuditReport(new AuditContext(), []);
        self::assertStringContainsString('Completed scan', \Dgtlss\Warden\Notifications\ReportMessage::title($clean));
        self::assertStringContainsString('No active findings', \Dgtlss\Warden\Notifications\ReportMessage::body($clean));
    }

    public function testEmailReceivesIncompleteReportAndDoesNotClaimSuccess(): void
    {
        $this->configureChannels();
        config(['warden.notifications.email.recipients' => 'security@example.com', 'warden.notifications.email.from_address' => 'warden@example.com', 'warden.notifications.on_errors' => true]);
        Mail::shouldReceive('raw')->once()->withArgs(static function (string $body, callable $callback): bool {
            self::assertStringContainsString('Scan incomplete', $body);
            self::assertStringContainsString('parse_error', $body);
            $message = new \Illuminate\Mail\Message(new \Symfony\Component\Mime\Email());
            $callback($message);
            self::assertStringContainsString('Incomplete scan', $message->getSymfonyMessage()->getSubject());
            return true;
        });
        self::assertSame([], (new NotificationDispatcher())->send(new AuditReport(new AuditContext(), [AuditResult::failed('source', 'parse_error', 'Fixture error')]), true));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('largeTeamsReports')]
    public function testTeamsPayloadIsBoundedWithoutLosingIncompleteStatus(string $title, string $error): void
    {
        $this->configureChannels(teams: 'https://example.com/teams');
        config(['warden.app_name' => $title]);
        $findings = [];
        for ($i = 1; $i <= 250; $i++) {
            $findings[] = new Finding('source.php.command-tainted-input', 'source', 'User-controlled input reaches a shell command',
                Severity::Critical, 'Request-controlled data reaches a security-sensitive operation.', path: 'app/Http/Controllers/Controller' . $i . '.php', line: 10);
        }

        Http::fake();
        $auditReport = new AuditReport(new AuditContext(), [new AuditResult('source', $findings, [
            new \Dgtlss\Warden\ValueObjects\AuditError('source', 'parse_error', $error),
        ])]);
        self::assertSame([], (new NotificationDispatcher())->send($auditReport, onlyOnFindings: true));
        Http::assertSentCount(1);
        Http::assertSent(static function ($request): bool {
            self::assertLessThanOrEqual(28000, strlen($request->body()));
            $payload = json_decode($request->body(), true, flags: JSON_THROW_ON_ERROR);
            self::assertStringContainsString('Incomplete scan', $payload['title']);
            self::assertStringContainsString('250 blocking findings, 0 advisory findings, 1 scan errors', $payload['text']);
            self::assertStringContainsString('Scan incomplete: no all-clear result is available.', $payload['text']);
            self::assertStringContainsString('ERROR [source/parse_error]', $payload['text']);
            self::assertStringContainsString('[Report truncated.', $payload['text']);
            self::assertTrue(mb_check_encoding($payload['text'], 'UTF-8'));
            return true;
        });
    }

    /** @return iterable<string, array{string, string}> */
    public static function largeTeamsReports(): iterable
    {
        yield 'ordinary findings' => ['Application', 'Invalid PHP syntax'];
        yield 'escaped Unicode and long application name' => [str_repeat('🛡️"', 1000), str_repeat("🔒\\\"\n", 5000)];
    }

    public function testBundledErrorPolicyDoesNotOptUsersIntoExtraAlerts(): void
    {
        self::assertNull(config('warden.notifications.on_errors'));
        $this->configureChannels(slack: 'https://example.com/slack');
        Http::fake();
        (new NotificationDispatcher())->send(new AuditReport(new AuditContext(), [AuditResult::failed('source', 'parse_error', 'Invalid syntax')]), true);
        Http::assertNothingSent();
    }

    public function testErrorOptInDoesNotConfigureChannels(): void
    {
        $this->configureChannels();
        config(['warden.notifications.on_errors' => true]);
        Http::fake();
        Mail::shouldReceive('raw')->never();
        Mail::shouldReceive('send')->never();
        self::assertSame([], (new NotificationDispatcher())->send(new AuditReport(new AuditContext(), [AuditResult::failed('source', 'parse_error', 'Invalid syntax')]), true));
        Http::assertNothingSent();
    }

    public function testCompletedEmailStillUsesExistingTemplateOverrides(): void
    {
        $this->configureChannels();
        config(['warden.notifications.email.recipients' => 'security@example.com', 'warden.notifications.email.from_address' => 'warden@example.com']);
        $path = sys_get_temp_dir() . '/warden-email-view-' . bin2hex(random_bytes(8));
        mkdir($path . '/mail', 0777, true);
        file_put_contents($path . '/mail/enhanced-report.blade.php', 'Existing custom template: {{ $totalFindings }} / {{ $findings[0]["title"] }}');
        $this->app['view']->getFinder()->prependNamespace('warden', $path);
        try {
            Mail::shouldReceive('send')->once()->withArgs(static function (string $view, array $data, callable $callback): bool {
                self::assertSame('warden::mail.enhanced-report', $view);
                self::assertSame('Existing custom template: 1 / Finding', view($view, $data)->render());
                self::assertSame('application', $data['findings'][0]['package']);
                self::assertArrayHasKey('fingerprint', $data['findings'][0]);
                return true;
            });
            Mail::shouldReceive('raw')->never();
            self::assertSame([], (new NotificationDispatcher())->send($this->report()));
        } finally {
            unlink($path . '/mail/enhanced-report.blade.php');
            rmdir($path . '/mail');
            rmdir($path);
        }
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
