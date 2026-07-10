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

final class NotificationDispatcherTest extends TestCase
{
    public function testConfiguredChannelIsDispatchedExactlyOnce(): void
    {
        Http::fake();
        config([
            'warden.notifications.slack.webhook_url' => 'https://example.com/slack',
            'warden.notifications.discord.webhook_url' => null,
            'warden.notifications.teams.webhook_url' => null,
            'warden.notifications.email.recipients' => null,
        ]);
        $finding = new Finding('test', 'test', 'Finding', Severity::High, 'Description');
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::complete('test', [$finding])]);

        self::assertSame([], (new NotificationDispatcher())->send($auditReport));
        Http::assertSentCount(1);
    }
}
