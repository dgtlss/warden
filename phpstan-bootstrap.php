<?php

/**
 * PHPStan Bootstrap for Warden Laravel Package
 *
 * This file provides stub implementations for Laravel-specific functions and classes
 * to allow PHPStan to analyze the package code without requiring the full Laravel
 * framework. The stubs handle common Laravel functionality like console commands,
 * configuration, and helper functions.
 *
 * Key stubs provided:
 * - Laravel Application and Console Command classes
 * - Laravel Facades (Facade, Log, Queue, Route, Session, View)
 * - Laravel helper functions (app, config, base_path, etc.)
 * - Laravel version constant
 *
 * These stubs allow PHPStan to understand the code structure while ignoring
 * the actual Laravel framework dependencies.
 */

if (!function_exists('app')) {
    function app() {
        return new class() {
            public function make($abstract) {
                return new stdClass();
            }
            public function offsetGet($key) {
                return new stdClass();
            }
        };
    }
}

if (!function_exists('config')) {
    function config($key, $default = null) {
        return $default;
    }
}

if (!function_exists('base_path')) {
    function base_path($path = '') {
        return __DIR__ . '/../' . ltrim($path, '/');
    }
}

if (!function_exists('storage_path')) {
    function storage_path($path = '') {
        return __DIR__ . '/../storage/' . ltrim($path, '/');
    }
}

if (!function_exists('resource_path')) {
    function resource_path($path = '') {
        return __DIR__ . '/../resources/' . ltrim($path, '/');
    }
}

if (!function_exists('database_path')) {
    function database_path($path = '') {
        return __DIR__ . '/../database/' . ltrim($path, '/');
    }
}

if (!function_exists('public_path')) {
    function public_path($path = '') {
        return __DIR__ . '/../public/' . ltrim($path, '/');
    }
}

if (!function_exists('env')) {
    function env($key, $default = null) {
        return $default;
    }
}

if (!function_exists('now')) {
    function now() {
        return new stdClass();
    }
}

if (!function_exists('today')) {
    function today() {
        return new stdClass();
    }
}

if (!class_exists('Illuminate\Foundation\Application')) {
    class Application extends stdClass {}
}

if (!class_exists('Illuminate\Console\Command')) {
    class Command extends stdClass {
        public function option($key = null) {
            return null;
        }
        public function info($message) {
            return null;
        }
        public function warn($message) {
            return null;
        }
        public function error($message) {
            return null;
        }
        public function newLine() {
            return null;
        }
        public function output() {
            return new class() {
                public function write($message) {}
                public function writeln($message) {}
            };
        }
    }
}

if (!class_exists('Illuminate\Support\Facades\Facade')) {
    class Facade extends stdClass {}
}

if (!class_exists('Illuminate\Support\Str')) {
    class Str extends stdClass {}
}

if (!class_exists('Illuminate\Support\Collection')) {
    class Collection extends stdClass {}
}

if (!class_exists('Illuminate\Support\Facades\Date')) {
    class Date extends stdClass {}
}

if (!class_exists('Illuminate\Support\Facades\Log')) {
    class Log extends stdClass {}
}

if (!class_exists('Illuminate\Support\Facades\Queue')) {
    class Queue extends stdClass {}
}

if (!class_exists('Illuminate\Support\Facades\Route')) {
    class Route extends stdClass {}
}

if (!class_exists('Illuminate\Support\Facades\Session')) {
    class Session extends stdClass {}
}

if (!class_exists('Illuminate\Support\Facades\View')) {
    class View extends stdClass {}
}

if (!defined('LARAVEL_VERSION')) {
    define('LARAVEL_VERSION', '10.0');
}

/**
 * @param string|null $key
 * @param mixed $default
 * @return mixed
 */
function config($key = null, $default = null) {
    return null;
}

/**
 * @param string|null $abstract
 * @return mixed
 */
function app($abstract = null) {
    return null;
}

/**
 * @param string|null $path
 * @return string
 */
function base_path($path = null) {
    return __DIR__;
}

/**
 * @param string|null $path
 * @return string
 */
function database_path($path = null) {
    return __DIR__ . '/database';
}

/**
 * @param string|null $path
 * @return string
 */
function config_path($path = null) {
    return __DIR__ . '/config';
}

/**
 * @param string $expression
 * @return void
 */
function info($expression) {
    // stub
}