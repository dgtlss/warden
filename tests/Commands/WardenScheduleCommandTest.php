<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Tests\TestCase;

class WardenScheduleCommandTest extends TestCase
{
    public function testScheduleCommandShowsStatus(): void
    {
        // Default behavior shows status
        $this->artisan('warden:schedule')
            ->expectsOutputToContain('Warden Schedule Status')
            ->expectsOutputToContain('Status:')
            ->assertExitCode(0);
    }

    public function testScheduleCommandWithStatusOption(): void
    {
        $this->artisan('warden:schedule --status')
            ->expectsOutputToContain('Warden Schedule Status')
            ->assertExitCode(0);
    }

    public function testScheduleCommandWithEnableOption(): void
    {
        // In test environment, .env might not exist
        // The command should handle this gracefully
        $this->artisan('warden:schedule --enable')
            ->expectsOutputToContain('Enabling Warden scheduled audits')
            ->expectsOutputToContain('Scheduled audits enabled')
            ->assertExitCode(0);
    }

    public function testScheduleCommandWithDisableOption(): void
    {
        // In test environment, .env might not exist
        // The command should handle this gracefully
        $this->artisan('warden:schedule --disable')
            ->expectsOutputToContain('Disabling Warden scheduled audits')
            ->expectsOutputToContain('Scheduled audits disabled')
            ->assertExitCode(0);
    }

    public function testEnableOptionShowsScheduleInfo(): void
    {
        // Enable option should show schedule configuration after enabling
        $this->artisan('warden:schedule --enable')
            ->expectsOutputToContain('Frequency:')
            ->expectsOutputToContain('Timezone:')
            ->expectsOutputToContain('Next audit will run:')
            ->expectsOutputToContain('Make sure your Laravel scheduler is running')
            ->assertExitCode(0);
    }

    public function testScheduleCommandShowsSchedulerCronHint(): void
    {
        // Enable to get to the schedule info display
        $this->artisan('warden:schedule --enable')
            ->expectsOutputToContain('php artisan schedule:run')
            ->assertExitCode(0);
    }
}
