<?php

use Carbon\Carbon;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Events\Dispatcher;

// Minimal Laravel stubs so PHPStan can analyse the package without the full framework.
// These are intentionally lightweight and only cover the pieces used by the package.

class WardenPHPStanFakeApplication extends Container
{
    public function version(): string
    {
        return 'fake-laravel-version';
    }
}

if (!class_exists(\Illuminate\Foundation\Application::class)) {
    class_alias(WardenPHPStanFakeApplication::class, \Illuminate\Foundation\Application::class);
}

class WardenPHPStanFakeCommand extends stdClass
{
    public function option($key = null) { return null; }
    public function info($message) { return null; }
    public function warn($message) { return null; }
    public function error($message) { return null; }
    public function newLine() { return null; }
    public function output() {
        return new class() {
            public function write($message) {}
            public function writeln($message) {}
        };
    }
}

if (!class_exists(\Illuminate\Console\Command::class)) {
    class_alias(WardenPHPStanFakeCommand::class, \Illuminate\Console\Command::class);
}

class WardenPHPStanFakeRouteDefinition
{
    public function uri(): string { return ''; }
    public function middleware(): array { return []; }
}

class WardenPHPStanFakeRouteFacade
{
    /** @return array<int, WardenPHPStanFakeRouteDefinition> */
    public static function getRoutes(): array
    {
        return [new WardenPHPStanFakeRouteDefinition()];
    }
}

if (!class_exists('Route')) {
    class_alias(WardenPHPStanFakeRouteFacade::class, 'Route');
}
if (!class_exists(\Illuminate\Support\Facades\Route::class)) {
    class_alias(WardenPHPStanFakeRouteFacade::class, \Illuminate\Support\Facades\Route::class);
}

$facadeStubs = [
    \Illuminate\Support\Facades\Facade::class,
    \Illuminate\Support\Facades\Date::class,
    \Illuminate\Support\Facades\Log::class,
    \Illuminate\Support\Facades\Queue::class,
    \Illuminate\Support\Facades\Session::class,
    \Illuminate\Support\Facades\View::class,
];

foreach ($facadeStubs as $facadeClass) {
    if (!class_exists($facadeClass)) {
        class_alias(stdClass::class, $facadeClass);
    }
}

if (!class_exists(\Illuminate\Support\Str::class)) { class_alias(stdClass::class, \Illuminate\Support\Str::class); }
if (!class_exists(\Illuminate\Support\Collection::class)) { class_alias(stdClass::class, \Illuminate\Support\Collection::class); }

if (!defined('LARAVEL_VERSION')) {
    define('LARAVEL_VERSION', '10.0');
}

if (!function_exists('app')) {
    /**
     * @param string|null $abstract
     * @return Container|stdClass
     */
    function app($abstract = null) {
        static $app;

        if ($app === null) {
            $app = new \Illuminate\Foundation\Application();
        }

        if ($abstract === null) {
            return $app;
        }

        if ($abstract === \Illuminate\Contracts\Container\Container::class) {
            return $app;
        }

        if ($abstract === DispatcherContract::class) {
            if (! $app->bound($abstract)) {
                $app->instance($abstract, class_exists(Dispatcher::class) ? new Dispatcher($app) : new stdClass());
            }

            return $app->make($abstract);
        }

        return $app->bound($abstract) ? $app->make($abstract) : new stdClass();
    }
}

if (!function_exists('config')) {
    /**
     * @param string|null $key
     * @param mixed $default
     * @return mixed
     */
    function config($key = null, $default = null) {
        return $default;
    }
}

if (!function_exists('base_path')) {
    function base_path($path = '') {
        return __DIR__ . '/../' . ltrim((string) $path, '/');
    }
}

if (!function_exists('storage_path')) {
    function storage_path($path = '') {
        return __DIR__ . '/../storage/' . ltrim((string) $path, '/');
    }
}

if (!function_exists('resource_path')) {
    function resource_path($path = '') {
        return __DIR__ . '/../resources/' . ltrim((string) $path, '/');
    }
}

if (!function_exists('database_path')) {
    function database_path($path = '') {
        return __DIR__ . '/../database/' . ltrim((string) $path, '/');
    }
}

if (!function_exists('public_path')) {
    function public_path($path = '') {
        return __DIR__ . '/../public/' . ltrim((string) $path, '/');
    }
}

if (!function_exists('env')) {
    function env($key, $default = null) {
        return $default;
    }
}

if (!function_exists('now')) {
    function now() {
        return Carbon::now();
    }
}

if (!function_exists('today')) {
    function today() {
        return Carbon::today();
    }
}

if (!function_exists('config_path')) {
    function config_path($path = null) {
        return __DIR__ . '/../config' . ($path ? '/' . ltrim((string) $path, '/') : '');
    }
}

if (!function_exists('info')) {
    function info($expression) {
        // stub
    }
}
