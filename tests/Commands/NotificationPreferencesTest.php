<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\AuditRunner;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\{AuditContext, AuditError, AuditReport, AuditResult, Finding};
use Illuminate\Support\Facades\{Artisan, Http, Mail};
use PHPUnit\Framework\Attributes\DataProvider;

final class NotificationPreferencesTest extends TestCase
{
    #[DataProvider('deliveryPreferences')]
    public function testDeliveryRespectsPreferences(string $channel, string $flag, bool $findingOnly, mixed $onErrors, bool $incomplete, string $findings, bool $deliver): void
    {
        $notifications = [
            'only_on_findings' => $findingOnly,
            'slack' => ['webhook_url' => $channel === 'slack' ? 'https://example.com/slack' : null],
            'discord' => ['webhook_url' => $channel === 'discord' ? 'https://example.com/discord' : null],
            'teams' => ['webhook_url' => $channel === 'teams' ? 'https://example.com/teams' : null],
            'email' => ['recipients' => $channel === 'email' ? 'security@example.com' : null, 'from_address' => 'warden@example.com', 'from_name' => 'Existing sender'],
        ];
        if ($onErrors !== 'missing') {
            $notifications['on_errors'] = $onErrors;
        }

        config(['warden.notifications' => $notifications]);
        // Simulate an existing published 2.1 config being merged with package defaults.
        (new \Dgtlss\Warden\Providers\WardenServiceProvider($this->app))->register();
        if ($onErrors === 'missing') {
            self::assertArrayNotHasKey('on_errors', config('warden.notifications'));
        }

        $finding = new Finding('test.high', 'test', 'Finding', Severity::High, 'Description');
        if ($findings === 'ignored') {
            config(['warden.ignore_findings' => [['id' => 'test.high', 'reason' => 'Reviewed', 'expires_at' => '2099-12-31']]]);
        }

        $auditReport = new AuditReport(new AuditContext(), [new AuditResult('test', $findings === 'none' ? [] : [$finding],
            $incomplete ? [new AuditError('test', 'scanner_failed', 'Registry unavailable')] : [])]);
        $this->mock(AuditRunner::class, static function ($mock) use ($auditReport): void {
            $mock->shouldReceive('run')->once()->andReturn($auditReport);
        });
        Http::fake();
        $mailCalls = 0;
        if ($channel === 'email' && $deliver) {
            $method = $incomplete ? 'raw' : 'send';
            Mail::shouldReceive($method)->once()->andReturnUsing(static function (...$arguments) use (&$mailCalls, $incomplete): void {
                $mailCalls++;
                if ($incomplete) {
                    self::assertStringContainsString('Scan incomplete: no all-clear result is available.', $arguments[0]);
                } else {
                    self::assertSame('warden::mail.enhanced-report', $arguments[0]);
                }
                $callback = $arguments[count($arguments) - 1];
                $message = new \Illuminate\Mail\Message(new \Symfony\Component\Mime\Email());
                $callback($message);
                self::assertSame('security@example.com', $message->getSymfonyMessage()->getTo()[0]->getAddress());
                self::assertSame('Existing sender', $message->getSymfonyMessage()->getFrom()[0]->getName());
                if ($incomplete) {
                    self::assertStringContainsString('Incomplete scan', $message->getSymfonyMessage()->getSubject());
                }
            });
            Mail::shouldReceive($incomplete ? 'send' : 'raw')->never();
        } else {
            Mail::shouldReceive('raw')->never();
            Mail::shouldReceive('send')->never();
        }

        $options = ['--format' => 'json', '--fail-on' => 'never'];
        if ($flag === 'both') {
            $options['--notify'] = $options['--notify-on-finding'] = true;
        } elseif ($flag !== 'none') {
            $options[$flag] = true;
        }

        self::assertSame($incomplete ? 2 : 0, Artisan::call('warden:audit', $options));
        $report = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($findings === 'ignored' ? 1 : 0, $report['summary']['ignored']);
        Http::assertSentCount($deliver && $channel !== 'email' ? 1 : 0);
        self::assertSame($deliver && $channel === 'email' ? 1 : 0, $mailCalls);
        foreach (Http::recorded() as [$request]) {
            if ($incomplete) {
                self::assertStringContainsString('Incomplete scan', $request->body());
                self::assertStringContainsString('Scan incomplete', $request->body());
                self::assertStringNotContainsString('All Clear', $request->body());
            }
        }
    }

    /** @return iterable<string, array{string, string, bool, mixed, bool, string, bool}> */
    public static function deliveryPreferences(): iterable
    {
        $cases = [
            // flag, configured filter, error setting, incomplete, findings, delivery
            'disabled clean' => ['none', false, 'missing', false, 'none', false],
            'disabled active' => ['none', true, 'missing', false, 'active', false],
            'disabled even with error opt-in' => ['none', true, true, true, 'active', false],
            'disabled error-only opt-in' => ['none', false, true, true, 'none', false],
            'notify clean' => ['--notify', false, 'missing', false, 'none', true],
            'notify error-only' => ['--notify', false, 'missing', true, 'none', true],
            'notify incomplete active' => ['--notify', false, null, true, 'active', true],
            'config filter completed empty' => ['--notify', true, 'missing', false, 'none', false],
            'config filter completed active' => ['--notify', true, null, false, 'active', true],
            'config filter errors missing' => ['--notify', true, 'missing', true, 'none', false],
            'config filter errors null' => ['--notify', true, null, true, 'none', false],
            'config filter errors active' => ['--notify', true, 'missing', true, 'active', true],
            'flag filter completed empty' => ['--notify-on-finding', false, 'missing', false, 'none', false],
            'flag filter completed active' => ['--notify-on-finding', false, 'missing', false, 'active', true],
            'flag filter errors missing' => ['--notify-on-finding', false, 'missing', true, 'none', false],
            'flag filter errors null' => ['--notify-on-finding', false, null, true, 'none', false],
            'flag filter errors active' => ['--notify-on-finding', false, null, true, 'active', true],
            'both flags preserve filter' => ['both', false, null, true, 'none', false],
            'ignored completed' => ['--notify-on-finding', false, null, false, 'ignored', false],
            'ignored incomplete' => ['--notify', true, 'missing', true, 'ignored', false],
            'explicit error opt-in with config' => ['--notify', true, true, true, 'none', true],
            'explicit error opt-in with flag' => ['--notify-on-finding', false, true, true, 'none', true],
            'explicit error opt-in ignored only' => ['both', true, true, true, 'ignored', true],
            'error opt-in does not bypass completed filter' => ['--notify-on-finding', true, true, false, 'none', false],
            'error opt-out empty' => ['--notify', false, false, true, 'none', false],
            'error opt-out active' => ['--notify', false, false, true, 'active', false],
            'error opt-out with filter active' => ['--notify-on-finding', true, false, true, 'active', false],
            'error opt-out leaves completed active' => ['--notify-on-finding', true, false, false, 'active', true],
            'error opt-out leaves completed empty notify' => ['--notify', false, false, false, 'none', true],
            'truthy string is not an explicit boolean opt-in' => ['--notify', true, 'true', true, 'none', false],
        ];
        foreach (['slack', 'discord', 'teams', 'email'] as $channel) {
            foreach ($cases as $name => $case) {
                yield $channel . ': ' . $name => [$channel, ...$case];
            }
        }
    }
}
