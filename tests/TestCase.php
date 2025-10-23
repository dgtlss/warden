<?php

namespace Dgtlss\Warden\Tests;

use Orchestra\Testbench\TestCase as OrchestraTestCase;
use Dgtlss\Warden\Providers\WardenServiceProvider;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            WardenServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // Setup default environment for tests
        $app['config']->set('warden.default_mode', 'ci');
        $app['config']->set('warden.cache_enabled', false);
        $app['config']->set('warden.notifications_enabled', false);
        
        // Configure test environment
        $app['config']->set('app.env', 'testing');
        $app['config']->set('app.debug', false);
    }
}