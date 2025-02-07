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
        // Check if APP_DEBUG is enabled in production only
        if (config('app.env') === 'production' && config('app.debug') === true) {
            $this->addFinding([
                'package' => 'app-config',
                'title' => 'Debug mode is enabled in production',
                'severity' => 'critical',
                'cve' => null,
                'affected_versions' => null
            ]);
        }

        // Only check for development packages if we're actually running in production
        if ($this->isActuallyProduction()) {
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
        $routeCollection = \Route::getRoutes();
        
        // Check debugbar routes separately as they're allowed when APP_DEBUG is true
        foreach ($routeCollection as $route) {
            $uri = $route->uri();
            if (str_starts_with($uri, '_debugbar')) {
                // Only flag debugbar routes as exposed if APP_DEBUG is false and there's no protective middleware
                if (!config('app.debug') && !$this->hasProtectiveMiddleware($route)) {
                    return true;
                }
                continue;
            }
            
            // Check other testing routes that should never be exposed in production
            $testingRoutes = [
                'telescope',
                'horizon',
                '_dusk',
            ];
            
            foreach ($testingRoutes as $testRoute) {
                if (str_starts_with($uri, $testRoute)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function hasProtectiveMiddleware($route): bool
    {
        $middleware = $route->middleware();
        $protectiveMiddleware = ['auth', 'admin', 'can:', 'ability:', 'role:','\Barryvdh\Debugbar\Middleware\DebugbarEnabled::class'];
        
        foreach ($middleware as $m) {
            foreach ($protectiveMiddleware as $protect) {
                if (str_starts_with($m, $protect)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private function isActuallyProduction(): bool
    {
        // Check for common CI/CD environment variables
        $ciEnvironments = [
            'CI',
            'CONTINUOUS_INTEGRATION',
            'GITHUB_ACTIONS',
            'GITLAB_CI',
            'JENKINS_URL',
            'TRAVIS',
            'CIRCLECI'
        ];

        foreach ($ciEnvironments as $env) {
            if (getenv($env) !== false) {
                return false;
            }
        }

        return config('app.env') === 'production';
    }
}
