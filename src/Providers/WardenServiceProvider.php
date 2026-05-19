<?php

namespace Dgtlss\Warden\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Console\Scheduling\Schedule;
use Dgtlss\Warden\Commands\WardenAuditCommand;
use Dgtlss\Warden\Commands\WardenAuditWorkerCommand;
use Dgtlss\Warden\Commands\WardenBaselineCommand;
use Dgtlss\Warden\Commands\WardenDoctorCommand;
use Dgtlss\Warden\Commands\WardenHistoryCommand;
use Dgtlss\Warden\Commands\WardenHistoryPruneCommand;
use Dgtlss\Warden\Commands\WardenResolveCommand;
use Dgtlss\Warden\Commands\WardenScheduleCommand;
use Dgtlss\Warden\Commands\WardenSyncCommand;
use Dgtlss\Warden\Commands\WardenSyntaxCommand;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\AuditExecutor;
use Dgtlss\Warden\Services\AuditHistoryService;
use Dgtlss\Warden\Services\AuditManager;
use Dgtlss\Warden\Services\AuditRegistry;
use Dgtlss\Warden\Services\BaselineService;
use Dgtlss\Warden\Services\CloudSyncService;
use Dgtlss\Warden\Services\FindingNormalizer;
use Dgtlss\Warden\Services\PolicyService;
use Dgtlss\Warden\Services\ProcessRunner;
use Dgtlss\Warden\Services\ReportFormatter;
use Dgtlss\Warden\Services\Resolve\ComposerResolver;
use Dgtlss\Warden\Services\Resolve\JavascriptResolver;
use Dgtlss\Warden\Services\ResolverRegistry;
use Dgtlss\Warden\Services\ResolutionExecutor;
use Dgtlss\Warden\Services\ResolutionPlanner;

class WardenServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/warden.php', 'warden');
        
        // Register services
        $this->app->singleton(AuditCacheService::class, function ($app) {
            return new AuditCacheService();
        });

        $this->app->singleton(AuditExecutor::class, function () {
            return new AuditExecutor();
        });

        $this->app->singleton(AuditRegistry::class, fn () => new AuditRegistry());
        $this->app->singleton(FindingNormalizer::class, fn () => new FindingNormalizer());
        $this->app->singleton(BaselineService::class, fn () => new BaselineService());
        $this->app->singleton(PolicyService::class, fn ($app) => new PolicyService($app->make(BaselineService::class)));
        $this->app->singleton(AuditHistoryService::class, fn () => new AuditHistoryService());
        $this->app->singleton(CloudSyncService::class, fn () => new CloudSyncService());
        $this->app->singleton(ProcessRunner::class, fn () => new ProcessRunner());
        $this->app->singleton(ComposerResolver::class, fn ($app) => new ComposerResolver($app->make(ProcessRunner::class)));
        $this->app->singleton(JavascriptResolver::class, fn ($app) => new JavascriptResolver($app->make(ProcessRunner::class)));
        $this->app->singleton(ResolverRegistry::class, fn ($app) => new ResolverRegistry(
            $app->make(ComposerResolver::class),
            $app->make(JavascriptResolver::class),
        ));
        $this->app->singleton(ResolutionPlanner::class, fn ($app) => new ResolutionPlanner($app->make(ResolverRegistry::class)));
        $this->app->singleton(ResolutionExecutor::class, fn ($app) => new ResolutionExecutor(
            $app->make(ProcessRunner::class),
            $app->make(AuditManager::class),
            $app->make(AuditHistoryService::class),
        ));
        $this->app->singleton(AuditManager::class, fn ($app) => new AuditManager(
            $app->make(AuditRegistry::class),
            $app->make(AuditExecutor::class),
            $app->make(AuditCacheService::class),
            $app->make(FindingNormalizer::class),
            $app->make(PolicyService::class),
            $app->make(AuditHistoryService::class),
            $app->make(CloudSyncService::class),
        ));
        $this->app->singleton(ReportFormatter::class, fn () => new ReportFormatter());
    }

    public function boot(): void
    {
        // Publish configuration
        $this->publishes([
            __DIR__.'/../config/warden.php' => config_path('warden.php'),
        ], 'warden-config');

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'warden-migrations');

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                WardenAuditCommand::class,
                WardenAuditWorkerCommand::class,
                WardenBaselineCommand::class,
                WardenDoctorCommand::class,
                WardenHistoryCommand::class,
                WardenHistoryPruneCommand::class,
                WardenResolveCommand::class,
                WardenScheduleCommand::class,
                WardenSyncCommand::class,
                WardenSyntaxCommand::class,
            ]);

            // Schedule the command if enabled
            if (config('warden.schedule.enabled', false)) {
                $this->app->booted(function (): void {
                    $schedule = $this->app->make(Schedule::class);
                    $frequency = config('warden.schedule.frequency', 'daily');
                    $time = config('warden.schedule.time', '03:00');
                    
                    $event = $schedule->command('warden:audit --no-notify');
                    
                    switch ($frequency) {
                        case 'hourly':
                            $event->hourly();
                            break;
                        case 'daily':
                            $event->dailyAt($time);
                            break;
                        case 'weekly':
                            $event->weeklyOn(1, $time); // Monday
                            break;
                        case 'monthly':
                            $event->monthlyOn(1, $time); // 1st of month
                            break;
                        default:
                            $event->daily();
                    }
                    
                    if ($timezone = config('warden.schedule.timezone')) {
                        $event->timezone($timezone);
                    }
                });
            }
        }

        $this->loadViewsFrom(__DIR__.'/../views', 'warden');
    }
}
