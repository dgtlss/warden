<?php

namespace Dgtlss\Warden\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Console\Scheduling\Schedule;
use Dgtlss\Warden\Commands\WardenAuditCommand;
use Dgtlss\Warden\Commands\WardenScheduleCommand;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\ParallelAuditExecutor;

class WardenServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/warden.php', 'warden');
        
        // Register services
        $this->app->singleton(AuditCacheService::class, function ($app) {
            return new AuditCacheService();
        });
        
        $this->app->bind(ParallelAuditExecutor::class, function ($app) {
            return new ParallelAuditExecutor();
        });
    }

    public function boot()
    {
        // Publish configuration
        $this->publishes([
            __DIR__.'/../config/warden.php' => config_path('warden.php'),
        ], 'warden-config');

        // Publish migrations
        if (config('warden.history.enabled', false)) {
            $this->publishes([
                __DIR__.'/../database/migrations/' => database_path('migrations'),
            ], 'warden-migrations');
        }

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                WardenAuditCommand::class,
                WardenScheduleCommand::class,
            ]);

            // Schedule the command if enabled
            if (config('warden.schedule.enabled', false)) {
                $this->app->booted(function () {
                    $schedule = $this->app->make(Schedule::class);
                    $frequency = config('warden.schedule.frequency', 'daily');
                    $time = config('warden.schedule.time', '03:00');
                    
                    $scheduledCommand = $schedule->command('warden:audit --silent');
                    
                    switch ($frequency) {
                        case 'hourly':
                            $scheduledCommand->hourly();
                            break;
                        case 'daily':
                            $scheduledCommand->dailyAt($time);
                            break;
                        case 'weekly':
                            $scheduledCommand->weeklyOn(1, $time); // Monday
                            break;
                        case 'monthly':
                            $scheduledCommand->monthlyOn(1, $time); // 1st of month
                            break;
                        default:
                            $scheduledCommand->daily();
                    }
                    
                    if ($timezone = config('warden.schedule.timezone')) {
                        $scheduledCommand->timezone($timezone);
                    }
                });
            }
        }

        $this->loadViewsFrom(__DIR__.'/../views', 'warden');
    }
}