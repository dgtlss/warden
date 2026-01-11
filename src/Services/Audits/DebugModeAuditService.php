<?php

namespace Dgtlss\Warden\Services\Audits;

class DebugModeAuditService extends AbstractAuditService
{
    /** @var array<int, string> */
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
            // Check for development packages in vendor/composer/installed.json
            $installedPackagesNames = $this->getInstalledPackagesNames();

            foreach ($this->devPackages as $devPackage) {
                if (in_array($devPackage, $installedPackagesNames)) {
                    $this->addFinding([
                        'package' => $devPackage,
                        'title' => 'Development package detected in production',
                        'severity' => 'high',
                        'cve' => null,
                        'affected_versions' => null
                    ]);
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

        // Check for exposed testing routes only in production
        if ($this->isActuallyProduction() && $this->hasExposedTestingRoutes()) {
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

    /**
     * @return array<int, string>
     */
    private function getInstalledPackagesNames(): array
    {
        $installedPackages = $this->getInstalledPackages();

        /** @var array<int, string> $names */
        $names = isset($installedPackages['packages']) && is_array($installedPackages['packages'])
            ? array_column($installedPackages['packages'], 'name')
            : [];
            
        return $names;
    }

    /**
     * @return array<string, mixed>
     */
    private function getInstalledPackages(): array
    {
        $installedPath = base_path('vendor/composer/installed.json');

        if (!file_exists($installedPath)) {
            return [];
        }

        $installedContents = file_get_contents($installedPath);
        if ($installedContents === false) {
            return [];
        }

        $decoded = json_decode($installedContents, true);
        /** @var array<string, mixed> $result */
        $result = is_array($decoded) ? $decoded : [];
        return $result;
    }

    private function hasExposedTestingRoutes(): bool
    {
        /** @var \Illuminate\Routing\RouteCollection $routeCollection */
        $routeCollection = \Illuminate\Support\Facades\Route::getRoutes();

        // Check debugbar routes separately as they're allowed when APP_DEBUG is true
        foreach ($routeCollection as $route) {
            if (!($route instanceof \Illuminate\Routing\Route)) {
                continue;
            }

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

            foreach ($testingRoutes as $testingRoute) {
                if (str_starts_with($uri, $testingRoute)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param \Illuminate\Routing\Route $route
     */
    private function hasProtectiveMiddleware($route): bool
    {
        /** @var array<int, string> $middleware */
        $middleware = $route->middleware();
        $protectiveMiddleware = [
            'auth',
            'admin',
            'can:',
            'ability:',
            'role:',
            'Barryvdh\Debugbar\Middleware\DebugbarEnabled'
        ];

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

        foreach ($ciEnvironments as $ciEnvironment) {
            if (getenv($ciEnvironment) !== false) {
                return false;
            }
        }

        return config('app.env') === 'production';
    }
}
