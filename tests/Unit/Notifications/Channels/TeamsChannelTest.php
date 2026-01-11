<?php

namespace Dgtlss\Warden\Tests\Unit\Notifications\Channels;

use Dgtlss\Warden\Notifications\Channels\TeamsChannel;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\Enums\Severity;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

class TeamsChannelTest extends TestCase
{
    public function testGetNameReturnsMicrosoftTeams(): void
    {
        $channel = new TeamsChannel();

        $this->assertEquals('Microsoft Teams', $channel->getName());
    }

    public function testIsConfiguredReturnsFalseWhenWebhookUrlIsNull(): void
    {
        Config::set('warden.notifications.teams.webhook_url', null);

        $channel = new TeamsChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsTrueWhenWebhookUrlIsSet(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');

        $channel = new TeamsChannel();

        $this->assertTrue($channel->isConfigured());
    }

    public function testSendDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.teams.webhook_url', null);

        Http::fake();

        $channel = new TeamsChannel();
        $channel->send([]);

        Http::assertNothingSent();
    }

    public function testSendPostsToWebhookUrl(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');
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

        $channel = new TeamsChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://outlook.office.com/webhook/test' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendIncludesCorrectAdaptiveCardStructure(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');
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

        $channel = new TeamsChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return isset($data['@type']) &&
                   $data['@type'] === 'MessageCard' &&
                   isset($data['sections']) &&
                   isset($data['summary']) &&
                   str_contains($data['summary'], 'Test App') &&
                   str_contains($data['summary'], '1 vulnerabilities found');
        });
    }

    public function testSendIncludesSeverityCounts(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package1',
                title: 'Critical vulnerability',
                severity: Severity::CRITICAL,
                affectedVersions: '<1.0',
            ),
            new Finding(
                source: 'composer',
                package: 'test/package2',
                title: 'High vulnerability',
                severity: Severity::HIGH,
                affectedVersions: '<2.0',
            ),
            new Finding(
                source: 'composer',
                package: 'test/package3',
                title: 'Medium vulnerability',
                severity: Severity::MEDIUM,
                affectedVersions: '<3.0',
            ),
        ];

        $channel = new TeamsChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            if (!isset($data['sections'][0]['facts'])) {
                return false;
            }

            $facts = $data['sections'][0]['facts'];
            $factsJson = (string) json_encode($facts);

            // Should include severity counts
            return str_contains($factsJson, 'Critical') &&
                   str_contains($factsJson, 'High') &&
                   str_contains($factsJson, 'Medium');
        });
    }

    public function testSendUsesCorrectSeverityColor(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');

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

        $channel = new TeamsChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            // Critical should use red theme color
            return isset($data['themeColor']) &&
                   $data['themeColor'] === 'FF0000';
        });
    }

    public function testSendSuccessCardWhenNoFindings(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $channel = new TeamsChannel();
        $channel->send([]);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return isset($data['themeColor']) &&
                   $data['themeColor'] === '00FF00' && // Green for success
                   str_contains($data['summary'], 'All Clear');
        });
    }

    public function testSendAbandonedPackagesDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.teams.webhook_url', null);

        Http::fake();

        $channel = new TeamsChannel();
        $channel->sendAbandonedPackages([]);

        Http::assertNothingSent();
    }

    public function testSendAbandonedPackagesPostsToWebhookUrl(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => 'new-package',
            ],
        ];

        $channel = new TeamsChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://outlook.office.com/webhook/test' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendAbandonedPackagesIncludesCorrectCard(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => 'new-package',
            ],
        ];

        $channel = new TeamsChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return isset($data['@type']) &&
                   $data['@type'] === 'MessageCard' &&
                   isset($data['summary']) &&
                   str_contains($data['summary'], 'Test App') &&
                   str_contains($data['summary'], '1 abandoned packages detected');
        });
    }

    public function testSendAbandonedPackagesIncludesReplacements(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => 'new-package',
            ],
        ];

        $channel = new TeamsChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();
            $dataJson = json_encode($data);

            return str_contains($dataJson, 'abandoned-package') &&
                   str_contains($dataJson, 'new-package') &&
                   str_contains($dataJson, 'Recommended');
        });
    }

    public function testSendAbandonedPackagesWithoutReplacement(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => null,
            ],
        ];

        $channel = new TeamsChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();
            $dataJson = json_encode($data);

            return str_contains($dataJson, 'abandoned-package') &&
                   str_contains($dataJson, 'No replacement suggested');
        });
    }

    public function testSendAbandonedPackagesIncludesActionButton(): void
    {
        Config::set('warden.notifications.teams.webhook_url', 'https://outlook.office.com/webhook/test');

        Http::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => null,
            ],
        ];

        $channel = new TeamsChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return isset($data['potentialAction']) &&
                   is_array($data['potentialAction']) &&
                   count($data['potentialAction']) > 0;
        });
    }
}
