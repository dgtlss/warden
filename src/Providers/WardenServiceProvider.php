<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Providers;

use Dgtlss\Warden\Commands\WardenAuditCommand;
use Dgtlss\Warden\Commands\WardenBaselineCommand;
use Dgtlss\Warden\Commands\WardenInitCommand;
use Dgtlss\Warden\Commands\WardenSyntaxCommand;
use Illuminate\Support\ServiceProvider;

final class WardenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/warden.php', 'warden');
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/warden.php' => config_path('warden.php'),
        ], 'warden-config');

        if ($this->app->runningInConsole()) {
            $this->commands([
                WardenAuditCommand::class,
                WardenBaselineCommand::class,
                WardenInitCommand::class,
                WardenSyntaxCommand::class,
            ]);
        }

        $this->loadViewsFrom(__DIR__ . '/../views', 'warden');
    }
}
