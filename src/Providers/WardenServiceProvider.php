<?php

namespace Dgtlss\Warden\Providers;

use Dgtlss\Warden\Commands\WardenAuditCommand;
use Dgtlss\Warden\Commands\WardenScheduleCommand;
use Dgtlss\Warden\Commands\WardenSetupCommand;
use Dgtlss\Warden\Commands\WardenSyntaxCommand;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Services\PluginManager;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

class WardenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/warden.php', 'warden');

        // Register services
        $this->app->singleton(AuditCacheService::class, function ($app) {
            return new AuditCacheService();
        });

        $this->app->bind(ParallelAuditExecutor::class, function ($app) {
            return new ParallelAuditExecutor();
        });

        // Register PluginManager singleton
        $this->app->singleton(PluginManager::class, function ($app) {
            /** @var \Illuminate\Contracts\Foundation\Application $app */
            return new PluginManager($app);
        });
    }

    public function boot(): void
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

        // Boot plugins
        $this->bootPlugins();

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->registerCommands();
            $this->registerSchedule();
        }

        $this->loadViewsFrom(__DIR__.'/../views', 'warden');
    }

    /**
     * Boot the plugin system.
     */
    protected function bootPlugins(): void
    {
        /** @var PluginManager $pluginManager */
        $pluginManager = $this->app->make(PluginManager::class);

        // Register plugins from config
        $pluginManager->registerFromConfig();

        // Auto-discover plugins from installed packages
        $pluginManager->discover();

        // Boot all registered plugins
        $pluginManager->boot();
    }

    /**
     * Register Artisan commands including plugin commands.
     */
    protected function registerCommands(): void
    {
        $coreCommands = [
            WardenAuditCommand::class,
            WardenScheduleCommand::class,
            WardenSetupCommand::class,
            WardenSyntaxCommand::class,
        ];

        // Get commands from plugins
        /** @var PluginManager $pluginManager */
        $pluginManager = $this->app->make(PluginManager::class);
        $pluginCommands = $pluginManager->getCommands();

        // Merge and register all commands
        $allCommands = array_merge($coreCommands, $pluginCommands);

        $this->commands($allCommands);
    }

    /**
     * Register the scheduled commands.
     */
    protected function registerSchedule(): void
    {
        if (!config('warden.schedule.enabled', false)) {
            return;
        }

        $this->app->booted(function (): void {
            $schedule = $this->app->make(Schedule::class);
            $frequencyConfig = config('warden.schedule.frequency', 'daily');
            $timeConfig = config('warden.schedule.time', '03:00');
            $frequency = is_string($frequencyConfig) ? $frequencyConfig : 'daily';
            $time = is_string($timeConfig) ? $timeConfig : '03:00';

            $event = match ($frequency) {
                'hourly' => $schedule->command('warden:audit')->hourly(),
                'daily' => $schedule->command('warden:audit')->dailyAt($time),
                'weekly' => $schedule->command('warden:audit')->weeklyOn(1, $time),
                'monthly' => $schedule->command('warden:audit')->monthlyOn(1, $time),
                default => $schedule->command('warden:audit')->dailyAt($time),
            };

            $timezone = config('warden.schedule.timezone');
            if (is_string($timezone)) {
                $event->timezone($timezone);
            }
        });
    }
}
