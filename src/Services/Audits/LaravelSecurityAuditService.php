<?php

namespace Dgtlss\Warden\Services\Audits;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Validator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use ReflectionClass;
use ReflectionMethod;

class LaravelSecurityAuditService extends AbstractAuditService
{
    protected array $routes = [];
    protected array $controllers = [];
    protected array $models = [];
    protected array $middleware = [];
    protected array $policies = [];

    public function getName(): string
    {
        return 'Laravel Security Audit';
    }

    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'scan_controllers' => true,
            'scan_models' => true,
            'scan_routes' => true,
            'scan_middleware' => true,
            'scan_policies' => true,
            'scan_views' => true,
            'scan_config' => true,
            'scan_migrations' => true,
            'scan_seeders' => true,
            'scan_requests' => true,
            'scan_resources' => true,
            'check_mass_assignment' => true,
            'check_sql_injection' => true,
            'check_xss' => true,
            'check_csrf' => true,
            'check_authentication' => true,
            'check_authorization' => true,
            'check_file_uploads' => true,
            'check_api_security' => true,
            'check_sensitive_data' => true,
            'check_debug_mode' => true,
            'check_env_exposure' => true,
            'check_route_protection' => true,
            'check_middleware_usage' => true,
            'check_validation' => true,
            'check_password_security' => true,
            'check_session_security' => true,
            'check_cache_security' => true,
            'check_queue_security' => true,
            'check_storage_security' => true,
            'severity_threshold' => 'medium',
            'exclude_paths' => [
                'vendor',
                'node_modules',
                'storage',
                'bootstrap/cache',
                'tests',
            ],
        ]);
    }

    protected function onInitialize(): void
    {
        $this->collectLaravelComponents();
    }

    protected function onShouldRun(): bool
    {
        // Check if we're in a Laravel application
        if (!function_exists('app') || !app()->bound('Illuminate\Foundation\Application')) {
            $this->info('Not a Laravel application - skipping Laravel security audit');
            return false;
        }

        return parent::onShouldRun();
    }

    public function run(): bool
    {
        if (!$this->shouldRun()) {
            return true;
        }

        $this->info('Starting Laravel Security Audit...');

        try {
            // Core Laravel security checks
            $this->checkCoreSecurity();
            
            // Framework component checks
            if ($this->getConfigValue('scan_routes', true)) {
                $this->checkRouteSecurity();
            }
            
            if ($this->getConfigValue('scan_controllers', true)) {
                $this->checkControllerSecurity();
            }
            
            if ($this->getConfigValue('scan_models', true)) {
                $this->checkModelSecurity();
            }
            
            if ($this->getConfigValue('scan_middleware', true)) {
                $this->checkMiddlewareSecurity();
            }
            
            if ($this->getConfigValue('scan_policies', true)) {
                $this->checkPolicySecurity();
            }
            
            if ($this->getConfigValue('scan_views', true)) {
                $this->checkViewSecurity();
            }
            
            if ($this->getConfigValue('scan_config', true)) {
                $this->checkConfigurationSecurity();
            }
            
            if ($this->getConfigValue('scan_requests', true)) {
                $this->checkRequestSecurity();
            }
            
            if ($this->getConfigValue('scan_resources', true)) {
                $this->checkResourceSecurity();
            }

            $this->info('Laravel Security Audit completed');
            return true;

        } catch (\Exception $e) {
            $this->addFinding([
                'component' => 'Laravel Security Audit',
                'title' => 'Audit execution failed',
                'severity' => 'high',
                'description' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]);
            
            $this->error("Laravel Security Audit failed: " . $e->getMessage());
            return false;
        }
    }

    protected function collectLaravelComponents(): void
    {
        try {
            // Collect routes
            $this->routes = collect(Route::getRoutes())->map(function ($route) {
                return [
                    'uri' => $route->uri(),
                    'methods' => $route->methods(),
                    'action' => $route->getActionName(),
                    'middleware' => $route->middleware(),
                    'name' => $route->getName(),
                ];
            })->toArray();

            // Collect controllers
            $this->controllers = $this->scanDirectory(app_path('Controllers'), 'Controller');

            // Collect models
            $this->models = $this->scanDirectory(app_path('Models'), 'Model');

            // Collect middleware
            $this->middleware = $this->scanDirectory(app_path('Http/Middleware'), 'Middleware');

            // Collect policies
            $this->policies = $this->scanDirectory(app_path('Policies'), 'Policy');

        } catch (\Exception $e) {
            $this->warning("Could not collect some Laravel components: " . $e->getMessage());
        }
    }

    protected function checkCoreSecurity(): void
    {
        $this->info('Checking core Laravel security...');

        // Check debug mode
        if ($this->getConfigValue('check_debug_mode', true)) {
            if (config('app.debug')) {
                $this->addFinding([
                    'component' => 'Core Configuration',
                    'title' => 'Debug mode enabled in production',
                    'severity' => 'high',
                    'description' => 'Debug mode should be disabled in production environments',
                    'file' => config_path('app.php'),
                    'recommendation' => 'Set APP_DEBUG=false in production'
                ]);
            }
        }

        // Check environment exposure
        if ($this->getConfigValue('check_env_exposure', true)) {
            $envUrl = config('app.env') === 'production' ? url('.env') : null;
            if ($envUrl && $this->checkUrlAccessible($envUrl)) {
                $this->addFinding([
                    'component' => 'Environment Security',
                    'title' => '.env file may be accessible',
                    'severity' => 'critical',
                    'description' => 'The .env file appears to be accessible via web server',
                    'recommendation' => 'Configure web server to deny access to .env files'
                ]);
            }
        }

        // Check application key
        if (config('app.key') === 'SomeRandomString') {
            $this->addFinding([
                'component' => 'Core Configuration',
                'title' => 'Default application key in use',
                'severity' => 'critical',
                'description' => 'The application is using the default encryption key',
                'file' => config_path('app.php'),
                'recommendation' => 'Run php artisan key:generate to set a proper encryption key'
            ]);
        }

        // Check session security
        if ($this->getConfigValue('check_session_security', true)) {
            $sessionDriver = config('session.driver');
            if ($sessionDriver === 'file') {
                $sessionPath = config('session.files');
                if ($sessionPath && strpos($sessionPath, public_path()) !== false) {
                    $this->addFinding([
                        'component' => 'Session Security',
                        'title' => 'Session files stored in public directory',
                        'severity' => 'high',
                        'description' => 'Session files are stored in a publicly accessible directory',
                        'recommendation' => 'Move session storage to a secure location outside public directory'
                    ]);
                }
            }
        }
    }

    protected function checkRouteSecurity(): void
    {
        $this->info('Checking route security...');

        foreach ($this->routes as $route) {
            // Check for unauthenticated admin routes
            if ($this->isAdminRoute($route['uri']) && !$this->hasAuthMiddleware($route['middleware'])) {
                $this->addFinding([
                    'component' => 'Route Security',
                    'title' => 'Unprotected admin route',
                    'severity' => 'high',
                    'description' => "Route {$route['uri']} appears to be an admin route without authentication",
                    'route' => $route['uri'],
                    'methods' => implode(', ', $route['methods']),
                    'recommendation' => 'Add authentication middleware to admin routes'
                ]);
            }

            // Check for routes without CSRF protection
            if (in_array('POST', $route['methods']) || in_array('PUT', $route['methods']) || in_array('DELETE', $route['methods'])) {
                if (!$this->hasCsrfMiddleware($route['middleware'])) {
                    $this->addFinding([
                        'component' => 'Route Security',
                        'title' => 'Route without CSRF protection',
                        'severity' => 'medium',
                        'description' => "Route {$route['uri']} accepts state-changing requests without CSRF protection",
                        'route' => $route['uri'],
                        'methods' => implode(', ', $route['methods']),
                        'recommendation' => 'Add VerifyCsrfToken middleware or use web middleware group'
                    ]);
                }
            }

            // Check for API routes without authentication
            if (str_starts_with($route['uri'], 'api/') && !$this->hasAuthMiddleware($route['middleware'])) {
                $this->addFinding([
                    'component' => 'API Security',
                    'title' => 'Unprotected API route',
                    'severity' => 'medium',
                    'description' => "API route {$route['uri']} lacks authentication middleware",
                    'route' => $route['uri'],
                    'recommendation' => 'Add authentication middleware to API routes'
                ]);
            }
        }
    }

    protected function checkControllerSecurity(): void
    {
        $this->info('Checking controller security...');

        foreach ($this->controllers as $controller) {
            $this->analyzeControllerFile($controller);
        }
    }

    protected function analyzeControllerFile(string $controller): void
    {
        try {
            $content = file_get_contents($controller);
            $reflection = new ReflectionClass($this->getClassNameFromFile($controller));

            foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                if ($method->getName() === '__construct') continue;

                $this->analyzeControllerMethod($method, $content, $controller);
            }
        } catch (\Exception $e) {
            $this->warning("Could not analyze controller {$controller}: " . $e->getMessage());
        }
    }

    protected function analyzeControllerMethod(ReflectionMethod $method, string $content, string $file): void
    {
        $methodName = $method->getName();
        $startLine = $method->getStartLine();
        $endLine = $method->getEndLine();
        
        $lines = file($file);
        $methodContent = implode('', array_slice($lines, $startLine - 1, $endLine - $startLine + 1));

        // Check for mass assignment vulnerabilities
        if ($this->getConfigValue('check_mass_assignment', true)) {
            if (preg_match('/\$request->all\(\)/', $methodContent) && !preg_match('/\$request->validate\(/', $methodContent)) {
                $this->addFinding([
                    'component' => 'Controller Security',
                    'title' => 'Potential mass assignment vulnerability',
                    'severity' => 'medium',
                    'description' => "Method {$methodName} uses \$request->all() without validation",
                    'file' => $file,
                    'line' => $startLine,
                    'recommendation' => 'Use \$request->only() with specific fields or implement proper validation'
                ]);
            }
        }

        // Check for direct database queries without validation
        if ($this->getConfigValue('check_sql_injection', true)) {
            if (preg_match('/DB::(select|insert|update|delete)\(.*\$.*\)/', $methodContent) && !preg_match('/\$request->validate\(/', $methodContent)) {
                $this->addFinding([
                    'component' => 'Controller Security',
                    'title' => 'Unvalidated database query with user input',
                    'severity' => 'high',
                    'description' => "Method {$methodName} uses direct database queries with potentially unvalidated user input",
                    'file' => $file,
                    'line' => $startLine,
                    'recommendation' => 'Validate user input before using in database queries or use parameterized queries'
                ]);
            }
        }

        // Check for file upload vulnerabilities
        if ($this->getConfigValue('check_file_uploads', true)) {
            if (preg_match('/\$request->file\(/', $methodContent) && !preg_match('/->validate\(/', $methodContent)) {
                $this->addFinding([
                    'component' => 'File Upload Security',
                    'title' => 'Unvalidated file upload',
                    'severity' => 'high',
                    'description' => "Method {$methodName} handles file uploads without proper validation",
                    'file' => $file,
                    'line' => $startLine,
                    'recommendation' => 'Validate file types, sizes, and implement proper file handling'
                ]);
            }
        }
    }

    protected function checkModelSecurity(): void
    {
        $this->info('Checking model security...');

        foreach ($this->models as $model) {
            $this->analyzeModelFile($model);
        }
    }

    protected function analyzeModelFile(string $model): void
    {
        try {
            $content = file_get_contents($model);
            $reflection = new ReflectionClass($this->getClassNameFromFile($model));

            // Check for mass assignment protection
            if ($this->getConfigValue('check_mass_assignment', true)) {
                if (!preg_match('/protected \$fillable\s*=\s*\[/', $content) && 
                    !preg_match('/protected \$guarded\s*=\s*\[/', $content)) {
                    $this->addFinding([
                        'component' => 'Model Security',
                        'title' => 'Model without mass assignment protection',
                        'severity' => 'medium',
                        'description' => "Model {$reflection->getName()} lacks fillable or guarded properties",
                        'file' => $model,
                        'recommendation' => 'Define $fillable or $guarded properties to prevent mass assignment vulnerabilities'
                    ]);
                }
            }

            // Check for hidden attributes
            if (!preg_match('/protected \$hidden\s*=\s*\[/', $content)) {
                $this->addFinding([
                    'component' => 'Model Security',
                    'title' => 'Model without hidden attributes',
                    'severity' => 'low',
                    'description' => "Model {$reflection->getName()} doesn't hide sensitive attributes",
                    'file' => $model,
                    'recommendation' => 'Define $hidden property to exclude sensitive fields from JSON responses'
                ]);
            }

        } catch (\Exception $e) {
            $this->warning("Could not analyze model {$model}: " . $e->getMessage());
        }
    }

    protected function checkMiddlewareSecurity(): void
    {
        $this->info('Checking middleware security...');

        foreach ($this->middleware as $middleware) {
            $this->analyzeMiddlewareFile($middleware);
        }
    }

    protected function analyzeMiddlewareFile(string $middleware): void
    {
        try {
            $content = file_get_contents($middleware);

            // Check for insecure redirects
            if (preg_match('/return redirect\(\$request->input\(/', $content)) {
                $this->addFinding([
                    'component' => 'Middleware Security',
                    'title' => 'Open redirect vulnerability',
                    'severity' => 'high',
                    'description' => 'Middleware performs redirect based on user input without validation',
                    'file' => $middleware,
                    'recommendation' => 'Validate redirect URLs to prevent open redirect attacks'
                ]);
            }

        } catch (\Exception $e) {
            $this->warning("Could not analyze middleware {$middleware}: " . $e->getMessage());
        }
    }

    protected function checkPolicySecurity(): void
    {
        $this->info('Checking policy security...');

        foreach ($this->policies as $policy) {
            $this->analyzePolicyFile($policy);
        }
    }

    protected function analyzePolicyFile(string $policy): void
    {
        try {
            $content = file_get_contents($policy);
            $reflection = new ReflectionClass($this->getClassNameFromFile($policy));

            foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                if ($method->getName() === '__construct') continue;

                // Check for policies that always return true
                $startLine = $method->getStartLine();
                $endLine = $method->getEndLine();
                
                $lines = file($policy);
                $methodContent = implode('', array_slice($lines, $startLine - 1, $endLine - $startLine + 1));

                if (preg_match('/return\s+true\s*;/', $methodContent)) {
                    $this->addFinding([
                        'component' => 'Policy Security',
                        'title' => 'Policy method always returns true',
                        'severity' => 'medium',
                        'description' => "Policy method {$method->getName()} always grants access",
                        'file' => $policy,
                        'line' => $startLine,
                        'recommendation' => 'Implement proper authorization logic in policy methods'
                    ]);
                }
            }

        } catch (\Exception $e) {
            $this->warning("Could not analyze policy {$policy}: " . $e->getMessage());
        }
    }

    protected function checkViewSecurity(): void
    {
        $this->info('Checking view security...');

        $viewPaths = [resource_path('views')];
        
        foreach ($viewPaths as $viewPath) {
            if (is_dir($viewPath)) {
                $this->scanViewDirectory($viewPath);
            }
        }
    }

    protected function scanViewDirectory(string $directory): void
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && in_array($file->getExtension(), ['php', 'blade.php'])) {
                $this->analyzeViewFile($file->getPathname());
            }
        }
    }

    protected function analyzeViewFile(string $view): void
    {
        try {
            $content = file_get_contents($view);

            // Check for unescaped output
            if (preg_match('/{!!\s*\$[^}]*!!}/', $content) && !preg_match('/{!!\s*\$[^}]*\|\s*raw\s*!!}/', $content)) {
                $this->addFinding([
                    'component' => 'View Security',
                    'title' => 'Unescaped output in view',
                    'severity' => 'medium',
                    'description' => 'View contains unescaped output which may lead to XSS',
                    'file' => $view,
                    'recommendation' => 'Use {{ }} for escaped output or ensure data is properly sanitized'
                ]);
            }

            // Check for hardcoded secrets
            if (preg_match('/(api[_-]?key|secret[_-]?key|password|token)\s*=\s*["\'][^"\']+["\']/', $content)) {
                $this->addFinding([
                    'component' => 'View Security',
                    'title' => 'Potential hardcoded secret in view',
                    'severity' => 'high',
                    'description' => 'View may contain hardcoded secrets or API keys',
                    'file' => $view,
                    'recommendation' => 'Move secrets to environment variables and use config() helper'
                ]);
            }

        } catch (\Exception $e) {
            $this->warning("Could not analyze view {$view}: " . $e->getMessage());
        }
    }

    protected function checkConfigurationSecurity(): void
    {
        $this->info('Checking configuration security...');

        $configFiles = glob(config_path() . '/*.php');
        
        foreach ($configFiles as $configFile) {
            $this->analyzeConfigFile($configFile);
        }
    }

    protected function analyzeConfigFile(string $configFile): void
    {
        try {
            $content = file_get_contents($configFile);
            $filename = basename($configFile, '.php');

            // Check for hardcoded credentials
            if (preg_match('/["\'][^"\']*(password|secret|key|token)["\']\s*=>\s*["\'][^"\']+["\']/', $content)) {
                $this->addFinding([
                    'component' => 'Configuration Security',
                    'title' => 'Potential hardcoded credentials in config',
                    'severity' => 'high',
                    'description' => "Configuration file {$filename} may contain hardcoded credentials",
                    'file' => $configFile,
                    'recommendation' => 'Use environment variables for sensitive configuration'
                ]);
            }

            // Check database.php for insecure settings
            if ($filename === 'database') {
                if (preg_match('/["\']charset["\']\s*=>\s*["\']utf8["\']/', $content)) {
                    $this->addFinding([
                        'component' => 'Database Configuration',
                        'title' => 'Using utf8 instead of utf8mb4',
                        'severity' => 'low',
                        'description' => 'Database charset should be utf8mb4 for full Unicode support',
                        'file' => $configFile,
                        'recommendation' => 'Change charset to utf8mb4 and collation to utf8mb4_unicode_ci'
                    ]);
                }
            }

        } catch (\Exception $e) {
            $this->warning("Could not analyze config {$configFile}: " . $e->getMessage());
        }
    }

    protected function checkRequestSecurity(): void
    {
        $this->info('Checking request security...');

        $requestPath = app_path('Http/Requests');
        if (is_dir($requestPath)) {
            $requests = $this->scanDirectory($requestPath, 'Request');
            
            foreach ($requests as $request) {
                $this->analyzeRequestFile($request);
            }
        }
    }

    protected function analyzeRequestFile(string $request): void
    {
        try {
            $content = file_get_contents($request);
            $reflection = new ReflectionClass($this->getClassNameFromFile($request));

            // Check if authorize() method exists and returns true
            if ($reflection->hasMethod('authorize')) {
                $method = $reflection->getMethod('authorize');
                $startLine = $method->getStartLine();
                $endLine = $method->getEndLine();
                
                $lines = file($request);
                $methodContent = implode('', array_slice($lines, $startLine - 1, $endLine - $startLine + 1));

                if (preg_match('/return\s+true\s*;/', $methodContent)) {
                    $this->addFinding([
                        'component' => 'Request Security',
                        'title' => 'Request authorization always returns true',
                        'severity' => 'medium',
                        'description' => 'Request class authorize() method always grants access',
                        'file' => $request,
                        'line' => $startLine,
                        'recommendation' => 'Implement proper authorization logic in request classes'
                    ]);
                }
            } else {
                $this->addFinding([
                    'component' => 'Request Security',
                    'title' => 'Request class missing authorization',
                    'severity' => 'medium',
                    'description' => 'Request class does not implement authorize() method',
                    'file' => $request,
                    'recommendation' => 'Implement authorize() method to control access to requests'
                ]);
            }

        } catch (\Exception $e) {
            $this->warning("Could not analyze request {$request}: " . $e->getMessage());
        }
    }

    protected function checkResourceSecurity(): void
    {
        $this->info('Checking resource security...');

        $resourcePath = app_path('Http/Resources');
        if (is_dir($resourcePath)) {
            $resources = $this->scanDirectory($resourcePath, 'Resource');
            
            foreach ($resources as $resource) {
                $this->analyzeResourceFile($resource);
            }
        }
    }

    protected function analyzeResourceFile(string $resource): void
    {
        try {
            $content = file_get_contents($resource);

            // Check for exposing sensitive data
            if (preg_match('/\$this->.*\s*=\s*\$this->.*->/', $content)) {
                $this->addFinding([
                    'component' => 'Resource Security',
                    'title' => 'Potential sensitive data exposure in resource',
                    'severity' => 'medium',
                    'description' => 'Resource may expose sensitive model attributes',
                    'file' => $resource,
                    'recommendation' => 'Review resource classes to ensure sensitive data is not exposed'
                ]);
            }

        } catch (\Exception $e) {
            $this->warning("Could not analyze resource {$resource}: " . $e->getMessage());
        }
    }

    // Helper methods
    protected function scanDirectory(string $directory, string $suffix = ''): array
    {
        $files = [];
        
        if (!is_dir($directory)) {
            return $files;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                if (empty($suffix) || str_contains($file->getFilename(), $suffix)) {
                    $files[] = $file->getPathname();
                }
            }
        }

        return $files;
    }

    protected function getClassNameFromFile(string $file): string
    {
        $content = file_get_contents($file);
        
        if (preg_match('/namespace\s+([^;]+);/', $content, $matches)) {
            $namespace = $matches[1];
        } else {
            $namespace = 'App';
        }

        if (preg_match('/class\s+(\w+)/', $content, $matches)) {
            $className = $matches[1];
        } else {
            $className = basename($file, '.php');
        }

        return $namespace . '\\' . $className;
    }

    protected function isAdminRoute(string $uri): bool
    {
        return str_contains($uri, 'admin') || 
               str_contains($uri, 'dashboard') || 
               str_contains($uri, 'management') ||
               preg_match('/^admin\//', $uri);
    }

    protected function hasAuthMiddleware(array $middleware): bool
    {
        $authMiddleware = ['auth', 'auth:api', 'auth:sanctum', 'auth.basic'];
        
        foreach ($middleware as $mid) {
            if (in_array($mid, $authMiddleware)) {
                return true;
            }
        }
        
        return false;
    }

    protected function hasCsrfMiddleware(array $middleware): bool
    {
        $csrfMiddleware = ['web', 'csrf', 'VerifyCsrfToken'];
        
        foreach ($middleware as $mid) {
            if (in_array($mid, $csrfMiddleware)) {
                return true;
            }
        }
        
        return false;
    }

    protected function checkUrlAccessible(string $url): bool
    {
        try {
            $client = new \GuzzleHttp\Client(['timeout' => 5]);
            $response = $client->head($url);
            return $response->getStatusCode() === 200;
        } catch (\Exception $e) {
            return false;
        }
    }
}