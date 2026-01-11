<?php

namespace Dgtlss\Warden\Tests\Unit\Notifications\Channels;

use Dgtlss\Warden\Notifications\Channels\DiscordChannel;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\Enums\Severity;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

class DiscordChannelTest extends TestCase
{
    public function testGetNameReturnsDiscord(): void
    {
        $channel = new DiscordChannel();

        $this->assertEquals('Discord', $channel->getName());
    }

    public function testIsConfiguredReturnsFalseWhenWebhookUrlIsNull(): void
    {
        Config::set('warden.notifications.discord.webhook_url', null);

        $channel = new DiscordChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsTrueWhenWebhookUrlIsSet(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');

        $channel = new DiscordChannel();

        $this->assertTrue($channel->isConfigured());
    }

    public function testSendDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.discord.webhook_url', null);

        Http::fake();

        $channel = new DiscordChannel();
        $channel->send([]);

        Http::assertNothingSent();
    }

    public function testSendPostsToWebhookUrl(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High severity vulnerability',
                severity: Severity::HIGH,
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new DiscordChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://discord.com/api/webhooks/test' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendIncludesCorrectEmbedsStructure(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High severity vulnerability',
                severity: Severity::HIGH,
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new DiscordChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return isset($data['embeds']) &&
                   isset($data['content']) &&
                   isset($data['username']) &&
                   $data['username'] === 'Warden Security' &&
                   str_contains($data['content'], 'Test App') &&
                   str_contains($data['content'], '1 vulnerabilities found');
        });
    }

    public function testSendGroupsFindingsBySource(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package1',
                title: 'Composer vulnerability',
                severity: Severity::HIGH,
                affectedVersions: '<1.0',
            ),
            new Finding(
                source: 'npm',
                package: 'test/package2',
                title: 'NPM vulnerability',
                severity: Severity::MEDIUM,
                affectedVersions: '<2.0',
            ),
        ];

        $channel = new DiscordChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            if (!isset($data['embeds']) || count($data['embeds']) < 2) {
                return false;
            }

            return true;
        });
    }

    public function testSendIncludesCveLinks(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Vulnerability with CVE',
                severity: Severity::CRITICAL,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new DiscordChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();
            $embedsJson = (string) json_encode($data['embeds']);

            return str_contains($embedsJson, 'CVE-2024-1234');
        });
    }

    public function testSendUsesCorrectSeverityColors(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Critical vulnerability',
                severity: Severity::CRITICAL,
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new DiscordChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            if (!isset($data['embeds'][0]['color'])) {
                return false;
            }

            // Critical should be red (0xFF0000 = 16711680)
            return $data['embeds'][0]['color'] === 0xFF0000;
        });
    }

    public function testSendAbandonedPackagesDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.discord.webhook_url', null);

        Http::fake();

        $channel = new DiscordChannel();
        $channel->sendAbandonedPackages([]);

        Http::assertNothingSent();
    }

    public function testSendAbandonedPackagesPostsToWebhookUrl(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => 'new-package',
            ],
        ];

        $channel = new DiscordChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://discord.com/api/webhooks/test' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendAbandonedPackagesIncludesCorrectEmbed(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => 'new-package',
            ],
        ];

        $channel = new DiscordChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return isset($data['embeds']) &&
                   count($data['embeds']) === 1 &&
                   isset($data['content']) &&
                   str_contains($data['content'], 'Test App') &&
                   str_contains($data['content'], '1 packages need attention');
        });
    }

    public function testSendAbandonedPackagesIncludesReplacements(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => 'new-package',
            ],
        ];

        $channel = new DiscordChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();
            $embedsJson = json_encode($data['embeds']);

            return str_contains($embedsJson, 'abandoned-package') &&
                   str_contains($embedsJson, 'new-package') &&
                   str_contains($embedsJson, 'Recommended');
        });
    }

    public function testSendAbandonedPackagesWithoutReplacement(): void
    {
        Config::set('warden.notifications.discord.webhook_url', 'https://discord.com/api/webhooks/test');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => null,
            ],
        ];

        $channel = new DiscordChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();
            $embedsJson = json_encode($data['embeds']);

            return str_contains($embedsJson, 'abandoned-package') &&
                   str_contains($embedsJson, 'No replacement suggested');
        });
    }
}
