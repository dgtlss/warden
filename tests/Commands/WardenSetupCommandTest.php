<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Tests\TestCase;

class WardenSetupCommandTest extends TestCase
{
    public function testSetupCommandWithShowEnvOption(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('WARDEN_SLACK_WEBHOOK_URL')
            ->expectsOutputToContain('WARDEN_CACHE_ENABLED')
            ->expectsOutputToContain('WARDEN_SCHEDULE_ENABLED')
            ->expectsOutputToContain('WARDEN_WEBHOOK_SIGNING_ENABLED')
            ->expectsOutputToContain('WARDEN_QUEUE_ENABLED')
            ->assertExitCode(0);
    }

    public function testSetupCommandShowsAllConfigSections(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('Notification Channels')
            ->expectsOutputToContain('Cache Settings')
            ->expectsOutputToContain('Scheduling')
            ->expectsOutputToContain('Security')
            ->expectsOutputToContain('Queue Processing')
            ->expectsOutputToContain('Audit History')
            ->expectsOutputToContain('Incremental Audits')
            ->assertExitCode(0);
    }

    public function testSetupCommandShowsDiscordConfig(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('WARDEN_DISCORD_WEBHOOK_URL')
            ->assertExitCode(0);
    }

    public function testSetupCommandShowsTeamsConfig(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('WARDEN_TEAMS_WEBHOOK_URL')
            ->assertExitCode(0);
    }

    public function testSetupCommandShowsEmailConfig(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('WARDEN_EMAIL_RECIPIENTS')
            ->assertExitCode(0);
    }

    public function testSetupCommandShowsRateLimitConfig(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('WARDEN_RATE_LIMIT_ENABLED')
            ->expectsOutputToContain('WARDEN_RATE_LIMIT_MAX_ATTEMPTS')
            ->assertExitCode(0);
    }

    public function testSetupCommandShowsHistoryConfig(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('WARDEN_HISTORY_ENABLED')
            ->expectsOutputToContain('WARDEN_HISTORY_RETENTION_DAYS')
            ->assertExitCode(0);
    }

    public function testSetupCommandShowsIncrementalConfig(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('WARDEN_INCREMENTAL_ENABLED')
            ->assertExitCode(0);
    }

    public function testSetupCommandShowsWebhookSecurityConfig(): void
    {
        $this->artisan('warden:setup --show-env')
            ->expectsOutputToContain('WARDEN_WEBHOOK_SECRET')
            ->assertExitCode(0);
    }
}
