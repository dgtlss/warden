<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Commands\WardenAuditCommand;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\AuditExecutor;
use Mockery\MockInterface;

class WardenAuditCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    public function testAuditCommandHandlesNoFindings(): void
    {
        $this->mock(AuditExecutor::class, function (MockInterface $mock): void {
            $mock->shouldReceive('addAudit')->zeroOrMoreTimes();
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->artisan('warden:audit')
            ->expectsOutputToContain('Warden')
            ->expectsOutputToContain('No security issues found.')
            ->assertExitCode(0);
    }

    public function testAuditCommandHandlesFindings(): void
    {
        $findings = [
            [
                'source' => 'composer',
                'title' => 'some/package - High severity vulnerability',
                'severity' => 'high',
                'package' => 'some/package',
            ],
        ];

        $this->mock(AuditExecutor::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('addAudit')->zeroOrMoreTimes();
            $mock->shouldReceive('execute')->once()->andReturn([
                'composer' => [
                    'success' => true,
                    'findings' => $findings,
                    'service' => new \stdClass(),
                ],
            ]);
        });

        $this->artisan('warden:audit', ['--no-notify' => true])
            ->expectsOutputToContain('Warden')
            ->expectsOutputToContain('1 security issue found.')
            ->assertExitCode(1);
    }
}
