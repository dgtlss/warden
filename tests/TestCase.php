<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests;

use Dgtlss\Warden\Providers\WardenServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }
}
