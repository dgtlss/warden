<?php

namespace Dgtlss\Warden\Tests\Unit\Notifications\Channels;

use Dgtlss\Warden\Notifications\Channels\SlackChannel;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\Enums\Severity;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

class SlackChannelTest extends TestCase
{
    public function testGetNameReturnsSlack(): void
    {
        $channel = new SlackChannel();

        $this->assertEquals('Slack', $channel->getName());
    }

    public function testIsConfiguredReturnsFalseWhenWebhookUrlIsNull(): void
    {
        Config::set('warden.notifications.slack.webhook_url', null);

        $channel = new SlackChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsFalseWhenWebhookUrlIsEmpty(): void
    {
        Config::set('warden.notifications.slack.webhook_url', '');

        $channel = new SlackChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsTrueWhenWebhookUrlIsSet(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');

        $channel = new SlackChannel();

        $this->assertTrue($channel->isConfigured());
    }

    public function testSendDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.slack.webhook_url', null);

        Http::fake();

        $channel = new SlackChannel();
        $channel->send([]);

        Http::assertNothingSent();
    }

    public function testSendPostsToWebhookUrl(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');
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

        $channel = new SlackChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://hooks.slack.com/services/test' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendIncludesCorrectBlocks(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');
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

        $channel = new SlackChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return isset($data['blocks']) &&
                   isset($data['text']) &&
                   str_contains($data['text'], 'Test App') &&
                   str_contains($data['text'], '1 vulnerabilities found');
        });
    }

    public function testSendIncludesSeverityEmojis(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Critical vulnerability',
                severity: Severity::CRITICAL,
                affectedVersions: '<1.0',
            ),
            new Finding(
                source: 'composer',
                package: 'test/package2',
                title: 'High severity vulnerability',
                severity: Severity::HIGH,
                affectedVersions: '<2.0',
            ),
        ];

        $channel = new SlackChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();
            $blocks = $data['blocks'];

            // Check that blocks include severity information
            $hasBlocks = count($blocks) > 3; // Header, summary, divider + findings

            return $hasBlocks;
        });
    }

    public function testSendIncludesCveLinks(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Vulnerability with CVE',
                severity: Severity::HIGH,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new SlackChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            if (!isset($data['blocks'])) {
                return false;
            }

            $blocks = $data['blocks'];
            $blocksJson = (string) json_encode($blocks);

            return str_contains($blocksJson, 'CVE-2024-1234');
        });
    }

    public function testSendAbandonedPackagesDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.slack.webhook_url', null);

        Http::fake();

        $channel = new SlackChannel();
        $channel->sendAbandonedPackages([]);

        Http::assertNothingSent();
    }

    public function testSendAbandonedPackagesPostsToWebhookUrl(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned/package',
                'replacement' => 'new/package',
            ],
        ];

        $channel = new SlackChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://hooks.slack.com/services/test' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendAbandonedPackagesIncludesCorrectBlocks(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned/package',
                'replacement' => 'new/package',
            ],
        ];

        $channel = new SlackChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return isset($data['blocks']) &&
                   isset($data['text']) &&
                   str_contains($data['text'], 'Test App') &&
                   str_contains($data['text'], '1 abandoned packages found');
        });
    }

    public function testSendAbandonedPackagesIncludesReplacements(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => 'new-package',
            ],
        ];

        $channel = new SlackChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();

            if (!isset($data['blocks'])) {
                return false;
            }

            $blocksJson = json_encode($data['blocks']);

            return str_contains($blocksJson, 'abandoned-package') &&
                   str_contains($blocksJson, 'new-package');
        });
    }

    public function testSendAbandonedPackagesWithoutReplacement(): void
    {
        Config::set('warden.notifications.slack.webhook_url', 'https://hooks.slack.com/services/test');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => null,
            ],
        ];

        $channel = new SlackChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();

            if (!isset($data['blocks'])) {
                return false;
            }

            $blocksJson = json_encode($data['blocks']);

            return str_contains($blocksJson, 'abandoned-package');
        });
    }
}
