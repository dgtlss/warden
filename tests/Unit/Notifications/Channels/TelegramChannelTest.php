<?php

namespace Dgtlss\Warden\Tests\Unit\Notifications\Channels;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Notifications\Channels\TelegramChannel;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

class TelegramChannelTest extends TestCase
{
    public function testGetNameReturnsTelegram(): void
    {
        $channel = new TelegramChannel();

        $this->assertEquals('telegram', $channel->getName());
    }

    public function testIsConfiguredReturnsFalseWhenBotTokenMissing(): void
    {
        Config::set('warden.notifications.telegram.bot_token', null);
        Config::set('warden.notifications.telegram.chat_id', '12345');

        $channel = new TelegramChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsFalseWhenChatIdMissing(): void
    {
        Config::set('warden.notifications.telegram.bot_token', 'token');
        Config::set('warden.notifications.telegram.chat_id', null);

        $channel = new TelegramChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsTrueWhenConfigured(): void
    {
        Config::set('warden.notifications.telegram.bot_token', 'token');
        Config::set('warden.notifications.telegram.chat_id', '12345');

        $channel = new TelegramChannel();

        $this->assertTrue($channel->isConfigured());
    }

    public function testSendDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.telegram.bot_token', null);
        Config::set('warden.notifications.telegram.chat_id', null);

        Http::fake();

        $channel = new TelegramChannel();
        $channel->send([]);

        Http::assertNothingSent();
    }

    public function testSendPostsToTelegramApi(): void
    {
        Config::set('warden.notifications.telegram.bot_token', 'token');
        Config::set('warden.notifications.telegram.chat_id', '12345');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High severity vulnerability',
                severity: Severity::HIGH,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new TelegramChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://api.telegram.org/bottoken/sendMessage' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendIncludesMessageDetails(): void
    {
        Config::set('warden.notifications.telegram.bot_token', 'token');
        Config::set('warden.notifications.telegram.chat_id', '12345');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High severity vulnerability',
                severity: Severity::HIGH,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new TelegramChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return $data['chat_id'] === '12345' &&
                   $data['parse_mode'] === 'HTML' &&
                   str_contains($data['text'], 'Test App') &&
                   str_contains($data['text'], '1') &&
                   str_contains($data['text'], 'CVE-2024-1234');
        });
    }

    public function testSendTruncatesAfterTenFindings(): void
    {
        Config::set('warden.notifications.telegram.bot_token', 'token');
        Config::set('warden.notifications.telegram.chat_id', '12345');

        Http::fake();

        $findings = [];
        for ($i = 1; $i <= 12; $i++) {
            $findings[] = new Finding(
                source: 'composer',
                package: "test/package{$i}",
                title: "Vulnerability {$i}",
                severity: Severity::LOW,
                affectedVersions: '<1.0',
            );
        }

        $channel = new TelegramChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return str_contains($data['text'], 'and 2 more');
        });
    }

    public function testSendAbandonedPackagesDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.telegram.bot_token', null);
        Config::set('warden.notifications.telegram.chat_id', null);

        Http::fake();

        $channel = new TelegramChannel();
        $channel->sendAbandonedPackages([]);

        Http::assertNothingSent();
    }

    public function testSendAbandonedPackagesPostsToTelegramApi(): void
    {
        Config::set('warden.notifications.telegram.bot_token', 'token');
        Config::set('warden.notifications.telegram.chat_id', '12345');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $abandonedPackages = [
            [
                'name' => 'abandoned/package',
                'replacement' => 'new/package',
            ],
        ];

        $channel = new TelegramChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://api.telegram.org/bottoken/sendMessage' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendAbandonedPackagesIncludesPackageDetails(): void
    {
        Config::set('warden.notifications.telegram.bot_token', 'token');
        Config::set('warden.notifications.telegram.chat_id', '12345');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $abandonedPackages = [
            [
                'name' => 'abandoned/package',
                'replacement' => 'new/package',
            ],
        ];

        $channel = new TelegramChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return str_contains($data['text'], 'abandoned/package') &&
                   str_contains($data['text'], 'new/package') &&
                   str_contains($data['text'], 'Test App');
        });
    }

    public function testSendAbandonedPackagesWithoutReplacement(): void
    {
        Config::set('warden.notifications.telegram.bot_token', 'token');
        Config::set('warden.notifications.telegram.chat_id', '12345');

        Http::fake();

        $abandonedPackages = [
            [
                'name' => 'abandoned/package',
                'replacement' => null,
            ],
        ];

        $channel = new TelegramChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return str_contains($data['text'], 'abandoned/package');
        });
    }
}
