<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Commands\WardenAuditCommand;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Dgtlss\Warden\Providers\WardenServiceProvider;

class ComposerAuditCommandTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [WardenServiceProvider::class];
    }

    public function testAuditCommand()
    {
        $this->artisan('warden:audit')
             ->assertExitCode(0);
    }
}