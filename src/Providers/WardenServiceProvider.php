<?php

namespace Dgtlss\Warden\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Console\Scheduling\Schedule;
use Dgtlss\Warden\Commands\WardenAuditCommand;

class WardenServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/warden.php', 'warden');
    }

    public function boot()
    {
        // Publish configuration
        $this->publishes([
            __DIR__.'/../config/warden.php' => config_path('warden.php'),
        ], 'warden-config');

        // Register command
        if ($this->app->runningInConsole()) {
            $this->commands([
                WardenAuditCommand::class,
            ]);

            // Schedule the command
            $this->app->booted(function () {
                $schedule = $this->app->make(Schedule::class);
                $schedule->command('warden:audit')->daily();
            });
        }

        $this->loadViewsFrom(__DIR__.'/../views', 'warden');
    }
}