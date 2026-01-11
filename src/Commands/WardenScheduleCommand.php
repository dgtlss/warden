<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Illuminate\Console\Scheduling\Schedule;

class WardenScheduleCommand extends Command
{
    protected $signature = 'warden:schedule 
        {--enable : Enable scheduled audits}
        {--disable : Disable scheduled audits}
        {--status : Show current schedule status}';

    protected $description = 'Manage Warden automated audit scheduling';

    public function handle(): int
    {
        if ($this->option('enable')) {
            return $this->enableSchedule();
        }

        if ($this->option('disable')) {
            return $this->disableSchedule();
        }

        if ($this->option('status')) {
            return $this->showStatus();
        }

        // Default: show status
        return $this->showStatus();
    }

    protected function enableSchedule(): int
    {
        $this->info('Enabling Warden scheduled audits...');
        
        // Update .env file
        $this->updateEnvironmentFile('WARDEN_SCHEDULE_ENABLED', 'true');
        
        $this->info('✓ Scheduled audits enabled');
        $this->info('');
        $this->showScheduleInfo();
        
        return 0;
    }

    protected function disableSchedule(): int
    {
        $this->info('Disabling Warden scheduled audits...');
        
        // Update .env file
        $this->updateEnvironmentFile('WARDEN_SCHEDULE_ENABLED', 'false');
        
        $this->info('✓ Scheduled audits disabled');
        
        return 0;
    }

    protected function showStatus(): int
    {
        $enabled = config('warden.schedule.enabled', false);
        
        $this->info('Warden Schedule Status');
        $this->info('======================');
        $this->info('');
        
        if ($enabled) {
            $this->info('Status: <fg=green>ENABLED</>');
            $this->showScheduleInfo();
        } else {
            $this->info('Status: <fg=red>DISABLED</>');
            $this->info('');
            $this->info('Run <fg=yellow>php artisan warden:schedule --enable</> to enable scheduled audits');
        }
        
        return 0;
    }

    protected function showScheduleInfo(): void
    {
        $frequencyConfig = config('warden.schedule.frequency', 'daily');
        $timeConfig = config('warden.schedule.time', '03:00');
        $timezoneConfig = config('warden.schedule.timezone', config('app.timezone'));

        $frequency = is_string($frequencyConfig) ? $frequencyConfig : 'daily';
        $time = is_string($timeConfig) ? $timeConfig : '03:00';
        $timezoneFallback = config('app.timezone', 'UTC');
        $timezone = is_string($timezoneConfig) ? $timezoneConfig : (is_string($timezoneFallback) ? $timezoneFallback : 'UTC');
        
        $this->info('');
        $this->info('Schedule Configuration:');
        $this->info(sprintf('  Frequency: <fg=yellow>%s</>', $frequency));
        
        if (in_array($frequency, ['daily', 'weekly', 'monthly'], true)) {
            $this->info(sprintf('  Time: <fg=yellow>%s</>', $time));
        }
        
        $this->info(sprintf('  Timezone: <fg=yellow>%s</>', $timezone));
        $this->info('');
        
        $nextRun = $this->calculateNextRunTime($frequency, $time);
        $this->info(sprintf('Next audit will run: <fg=green>%s</>', $nextRun));
        
        $this->info('');
        $this->info('Note: Make sure your Laravel scheduler is running:');
        $this->info('  <fg=yellow>* * * * * cd /path-to-your-project && php artisan schedule:run >> /dev/null 2>&1</>');
    }

    protected function calculateNextRunTime(string $frequency, string $time): string
    {
        $now = now();
        
        switch ($frequency) {
            case 'hourly':
                return $now->addHour()->startOfHour()->format('Y-m-d H:i:s T');
                
            case 'daily':
                $scheduledTime = today()->setTimeFromTimeString($time);
                if ($scheduledTime->isPast()) {
                    $scheduledTime->addDay();
                }

                return $scheduledTime->format('Y-m-d H:i:s T');
                
            case 'weekly':
                $scheduledTime = today()->setTimeFromTimeString($time);
                if ($scheduledTime->isPast()) {
                    $scheduledTime->addWeek();
                }

                return $scheduledTime->startOfWeek()->format('Y-m-d H:i:s T');
                
            case 'monthly':
                $scheduledTime = today()->setTimeFromTimeString($time);
                if ($scheduledTime->isPast()) {
                    $scheduledTime->addMonth();
                }

                return $scheduledTime->startOfMonth()->format('Y-m-d H:i:s T');
                
            default:
                return 'Unknown';
        }
    }

    protected function updateEnvironmentFile(string $key, string $value): void
    {
        $path = base_path('.env');
        
        if (!file_exists($path)) {
            return;
        }
        
        $content = file_get_contents($path);
        if ($content === false) {
            return;
        }
        
        $pattern = sprintf('/^%s=.*/m', $key);
        
        if (preg_match($pattern, $content)) {
            $content = preg_replace(
                $pattern,
                sprintf('%s=%s', $key, $value),
                $content
            );
        } else {
            $content .= sprintf('%s%s=%s%s', PHP_EOL, $key, $value, PHP_EOL);
        }
        
        file_put_contents($path, $content);
    }
}
