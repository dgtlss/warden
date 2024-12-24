<?php

namespace Dgtlss\Warden\Services\Audits;

class DebugModeAuditService extends AbstractAuditService
{
    private array $devPackages = [
        'barryvdh/laravel-debugbar',
        'laravel/telescope',
        'laravel/horizon',
        'beyondcode/laravel-dump-server',
        'laravel/dusk',
    ];

    public function getName(): string
    {
        return 'debug-mode';
    }

    public function run(): bool
    {
        // Check if APP_DEBUG is enabled
        if (config('app.debug') === true) {
            $this->addFinding([
                'package' => 'app-config',
                'title' => 'Debug mode is enabled',
                'severity' => 'critical',
                'cve' => null,
                'affected_versions' => null
            ]);
        }

        // Check if APP_ENV is production but debug features are enabled
        if (config('app.env') === 'production') {
            // Check for development packages in composer.json
            $composerJson = $this->getComposerJson();
            if ($composerJson) {
                $installedPackages = array_merge(
                    array_keys($composerJson['require'] ?? []),
                    array_keys($composerJson['require-dev'] ?? [])
                );

                foreach ($this->devPackages as $package) {
                    if (in_array($package, $installedPackages)) {
                        $this->addFinding([
                            'package' => $package,
                            'title' => 'Development package detected in production',
                            'severity' => 'high',
                            'cve' => null,
                            'affected_versions' => null
                        ]);
                    }
                }
            }

            // Check if Telescope is enabled
            if (class_exists(\Laravel\Telescope\Telescope::class) && config('telescope.enabled')) {
                $this->addFinding([
                    'package' => 'laravel/telescope',
                    'title' => 'Laravel Telescope is enabled in production',
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null
                ]);
            }

            // Check if Horizon is enabled
            if (class_exists(\Laravel\Horizon\Horizon::class) && config('horizon.enabled')) {
                $this->addFinding([
                    'package' => 'laravel/horizon',
                    'title' => 'Laravel Horizon dashboard is enabled in production',
                    'severity' => 'medium',
                    'cve' => null,
                    'affected_versions' => null
                ]);
            }
        }

        // Check for exposed testing routes
        if ($this->hasExposedTestingRoutes()) {
            $this->addFinding([
                'package' => 'routes',
                'title' => 'Testing routes are exposed',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null
            ]);
        }

        return true;
    }

    private function getComposerJson(): ?array
    {
        $composerPath = base_path('composer.json');
        if (!file_exists($composerPath)) {
            return null;
        }

        return json_decode(file_get_contents($composerPath), true);
    }

    private function hasExposedTestingRoutes(): bool
    {
        // Check common testing routes that shouldn't be accessible in production
        $testingRoutes = [
            'telescope',
            'horizon',
            '_dusk',
            '_debugbar',
        ];

        $routeCollection = \Route::getRoutes();
        foreach ($routeCollection as $route) {
            $uri = $route->uri();
            foreach ($testingRoutes as $testRoute) {
                if (str_starts_with($uri, $testRoute)) {
                    return true;
                }
            }
        }

        return false;
    }
}
