<?php

namespace Dgtlss\Warden\Tests\Unit\Notifications\Channels;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Notifications\Channels\PagerDutyChannel;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

class PagerDutyChannelTest extends TestCase
{
    public function testGetNameReturnsPagerDuty(): void
    {
        $channel = new PagerDutyChannel();

        $this->assertEquals('pagerduty', $channel->getName());
    }

    public function testIsConfiguredReturnsFalseWhenIntegrationKeyMissing(): void
    {
        Config::set('warden.notifications.pagerduty.integration_key', null);

        $channel = new PagerDutyChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsTrueWhenIntegrationKeySet(): void
    {
        Config::set('warden.notifications.pagerduty.integration_key', 'test-key');

        $channel = new PagerDutyChannel();

        $this->assertTrue($channel->isConfigured());
    }

    public function testSendDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.pagerduty.integration_key', null);

        Http::fake();

        $channel = new PagerDutyChannel();
        $channel->send([]);

        Http::assertNothingSent();
    }

    public function testSendDoesNotSendWhenOnlyLowSeverityFindings(): void
    {
        Config::set('warden.notifications.pagerduty.integration_key', 'test-key');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Low vulnerability',
                severity: Severity::LOW,
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new PagerDutyChannel();
        $channel->send($findings);

        Http::assertNothingSent();
    }

    public function testSendPostsToPagerDutyForCriticalFindings(): void
    {
        Config::set('warden.notifications.pagerduty.integration_key', 'test-key');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Critical vulnerability',
                severity: Severity::CRITICAL,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
        ];

        $channel = new PagerDutyChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://events.pagerduty.com/v2/enqueue' &&
                   $request->method() === 'POST';
        });
    }

    public function testSendPayloadIncludesSummaryAndDetails(): void
    {
        Config::set('warden.notifications.pagerduty.integration_key', 'test-key');
        Config::set('warden.app_name', 'Test App');

        Http::fake();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High vulnerability',
                severity: Severity::HIGH,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
            new Finding(
                source: 'npm',
                package: 'test/npm',
                title: 'Medium vulnerability',
                severity: Severity::MEDIUM,
                affectedVersions: '<2.0',
            ),
        ];

        $channel = new PagerDutyChannel();
        $channel->send($findings);

        Http::assertSent(function ($request) {
            $data = $request->data();

            return $data['routing_key'] === 'test-key' &&
                   $data['event_action'] === 'trigger' &&
                   isset($data['payload']['summary']) &&
                   str_contains($data['payload']['summary'], 'Test App') &&
                   $data['payload']['severity'] === 'error' &&
                   isset($data['payload']['custom_details']['total_findings']);
        });
    }

    public function testSendAbandonedPackagesDoesNotSend(): void
    {
        Config::set('warden.notifications.pagerduty.integration_key', 'test-key');

        Http::fake();

        $channel = new PagerDutyChannel();
        $channel->sendAbandonedPackages([
            [
                'package' => 'abandoned/package',
                'replacement' => 'new/package',
            ],
        ]);

        Http::assertNothingSent();
    }
}
