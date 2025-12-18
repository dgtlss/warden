<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Commands\WardenAuditCommand;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Mockery\MockInterface;

class WardenAuditCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    public function testAuditCommandHandlesNoFindings()
    {
        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock): void {
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->artisan('warden:audit')
            ->expectsOutputToContain('Warden Security Audit')
            ->expectsOutputToContain('✅ No security issues found.')
            ->assertExitCode(0);
    }

    public function testAuditCommandHandlesFindings()
    {
        $findings = [
            [
                'source' => 'composer',
                'title' => 'some/package - High severity vulnerability',
                'severity' => 'high',
            ],
        ];

        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('execute')->once()->andReturn($findings);
        });

        $this->artisan('warden:audit')
            ->expectsOutputToContain('Warden Security Audit')
            ->expectsOutputToContain('1 security issues found.')
            ->assertExitCode(1);
    }
}