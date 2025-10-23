<?php

namespace Dgtlss\Warden\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Console\Scheduling\Schedule;
use Dgtlss\Warden\Commands\WardenAuditCommand;
use Dgtlss\Warden\Commands\WardenScheduleCommand;
use Dgtlss\Warden\Commands\WardenSyntaxCommand;
use Dgtlss\Warden\Commands\WardenPluginCommand;
use Dgtlss\Warden\Commands\WardenHelpCommand;
use Dgtlss\Warden\Commands\WardenConfigCommand;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Services\PluginManager;
use Dgtlss\Warden\Services\Dependencies\DependencyResolver;
use Dgtlss\Warden\Plugins\CoreAuditPlugin;
use Dgtlss\Warden\Contracts\PluginManagerInterface;

class WardenServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/warden.php', 'warden');
        
        // Register core services
        $this->app->singleton(AuditCacheService::class, function ($app) {
            return new AuditCacheService();
        });
        
        $this->app->bind(ParallelAuditExecutor::class, function ($app) {
            return new ParallelAuditExecutor();
        });

        // Register plugin manager
        $this->app->singleton(PluginManagerInterface::class, function ($app) {
            return new PluginManager();
        });

        $this->app->alias(PluginManagerInterface::class, 'warden.plugin_manager');

        // Register dependency resolver
        $this->app->singleton(DependencyResolver::class, function ($app) {
            $pluginManager = $app->make(PluginManagerInterface::class);
            return new DependencyResolver($pluginManager);
        });

        $this->app->alias(DependencyResolver::class, 'warden.dependency_resolver');
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

        // Initialize plugin system
        $this->initializePluginSystem();

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                WardenAuditCommand::class,
                WardenScheduleCommand::class,
                WardenSyntaxCommand::class,
                WardenPluginCommand::class,
                WardenHelpCommand::class,
                WardenConfigCommand::class,
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

    /**
     * Initialize the plugin system.
     *
     * @return void
     */
    protected function initializePluginSystem(): void
    {
        $pluginManager = $this->app->make(PluginManagerInterface::class);
        $dependencyResolver = $this->app->make(DependencyResolver::class);

        // Register the core audit plugin
        $corePlugin = new CoreAuditPlugin($dependencyResolver);
        $pluginManager->register($corePlugin);

        // Discover additional plugins if enabled
        if (config('warden.plugins.auto_discover', true)) {
            $pluginManager->discoverPlugins();
        }

        // Register plugins from configuration
        $configuredPlugins = config('warden.plugins.register', []);
        foreach ($configuredPlugins as $pluginClass) {
            if (class_exists($pluginClass)) {
                try {
                    $plugin = $this->app->make($pluginClass);
                    if ($plugin instanceof \Dgtlss\Warden\Contracts\AuditPluginInterface) {
                        $pluginManager->register($plugin);
                    }
                } catch (\Exception $e) {
                    \Log::error("Failed to register plugin {$pluginClass}: " . $e->getMessage());
                }
            }
        }
    }
}