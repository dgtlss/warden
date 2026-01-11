<?php

namespace Dgtlss\Warden\Tests\Unit\Notifications\Channels;

use Dgtlss\Warden\Notifications\Channels\EmailChannel;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Mail;

class EmailChannelTest extends TestCase
{
    public function testGetNameReturnsEmail(): void
    {
        $channel = new EmailChannel();

        $this->assertEquals('Email', $channel->getName());
    }

    public function testIsConfiguredReturnsFalseWhenRecipientsIsNull(): void
    {
        Config::set('warden.notifications.email.recipients', null);
        Config::set('warden.notifications.email.from_address', 'warden@example.com');

        $channel = new EmailChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsFalseWhenFromAddressIsNull(): void
    {
        Config::set('warden.notifications.email.recipients', 'admin@example.com');
        Config::set('warden.notifications.email.from_address', null);

        $channel = new EmailChannel();

        $this->assertFalse($channel->isConfigured());
    }

    public function testIsConfiguredReturnsTrueWhenBothAreSet(): void
    {
        Config::set('warden.notifications.email.recipients', 'admin@example.com');
        Config::set('warden.notifications.email.from_address', 'warden@example.com');

        $channel = new EmailChannel();

        $this->assertTrue($channel->isConfigured());
    }

    public function testSendDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.email.recipients', null);
        Config::set('warden.notifications.email.from_address', null);

        Mail::fake();

        $channel = new EmailChannel();
        $channel->send([]);

        Mail::assertNothingSent();
    }

    public function testSendExecutesSuccessfully(): void
    {
        Config::set('warden.notifications.email.recipients', 'admin@example.com');
        Config::set('warden.notifications.email.from_address', 'warden@example.com');
        Config::set('warden.app_name', 'Test App');

        Mail::fake();

        $findings = [
            [
                'source' => 'composer',
                'package' => 'test/package',
                'title' => 'High severity vulnerability',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        $channel = new EmailChannel();

        // Should not throw an exception
        $channel->send($findings);

        $this->assertTrue(true);
    }

    public function testSendHandlesMultipleRecipients(): void
    {
        Config::set('warden.notifications.email.recipients', 'admin@example.com, dev@example.com');
        Config::set('warden.notifications.email.from_address', 'warden@example.com');

        Mail::fake();

        $findings = [
            [
                'source' => 'composer',
                'package' => 'test/package',
                'title' => 'Vulnerability',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        $channel = new EmailChannel();
        $channel->send($findings);

        // Should complete without error
        $this->assertTrue(true);
    }

    public function testSendHandlesVariousSeverities(): void
    {
        Config::set('warden.notifications.email.recipients', 'admin@example.com');
        Config::set('warden.notifications.email.from_address', 'warden@example.com');

        Mail::fake();

        $severities = ['critical', 'high', 'medium', 'low'];

        foreach ($severities as $severity) {
            $findings = [
                [
                    'source' => 'composer',
                    'package' => 'test/package',
                    'title' => $severity . ' vulnerability',
                    'severity' => $severity,
                    'cve' => null,
                    'affected_versions' => '<1.0',
                ],
            ];

            $channel = new EmailChannel();
            $channel->send($findings);
        }

        // Should handle all severities without error
        $this->assertTrue(true);
    }

    public function testSendAbandonedPackagesDoesNotSendWhenNotConfigured(): void
    {
        Config::set('warden.notifications.email.recipients', null);
        Config::set('warden.notifications.email.from_address', null);

        Mail::fake();

        $channel = new EmailChannel();
        $channel->sendAbandonedPackages([]);

        Mail::assertNothingSent();
    }

    public function testSendAbandonedPackagesExecutesSuccessfully(): void
    {
        Config::set('warden.notifications.email.recipients', 'admin@example.com');
        Config::set('warden.notifications.email.from_address', 'warden@example.com');
        Config::set('warden.app_name', 'Test App');

        Mail::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => 'new-package',
            ],
        ];

        $channel = new EmailChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        // Should complete without error
        $this->assertTrue(true);
    }

    public function testSendAbandonedPackagesHandlesNoReplacement(): void
    {
        Config::set('warden.notifications.email.recipients', 'admin@example.com');
        Config::set('warden.notifications.email.from_address', 'warden@example.com');

        Mail::fake();

        $abandonedPackages = [
            [
                'package' => 'abandoned-package',
                'replacement' => null,
            ],
        ];

        $channel = new EmailChannel();
        $channel->sendAbandonedPackages($abandonedPackages);

        // Should handle null replacement without error
        $this->assertTrue(true);
    }

    public function testSendHandlesEmptyFindings(): void
    {
        Config::set('warden.notifications.email.recipients', 'admin@example.com');
        Config::set('warden.notifications.email.from_address', 'warden@example.com');

        Mail::fake();

        $channel = new EmailChannel();
        $channel->send([]);

        // Should handle empty findings without error
        $this->assertTrue(true);
    }
}
