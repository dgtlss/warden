<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Illuminate\Support\Facades\Config;
use Mockery\MockInterface;

class WardenAuditCommandTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Enable parallel execution for these tests so mocking works
        Config::set('warden.audits.parallel_execution', true);
    }

    public function testAuditCommandHandlesNoFindings(): void
    {
        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock): void {
            $mock->shouldReceive('addAudit')->andReturnSelf();
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->artisan('warden:audit --silent')
            ->assertExitCode(0);
    }

    public function testAuditCommandHandlesFindings(): void
    {
        $mockService = \Mockery::mock();
        $mockService->shouldReceive('getName')->andReturn('composer');
        $mockService->shouldReceive('getAbandonedPackages')->andReturn([]);

        $results = [
            'composer' => [
                'success' => true,
                'findings' => [
                    [
                        'source' => 'composer',
                        'package' => 'test/package',
                        'title' => 'High severity vulnerability',
                        'severity' => 'high',
                        'cve' => 'CVE-2024-1234',
                        'affected_versions' => '<1.0',
                    ],
                ],
                'service' => $mockService,
            ],
        ];

        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock) use ($results): void {
            $mock->shouldReceive('addAudit')->andReturnSelf();
            $mock->shouldReceive('execute')->once()->andReturn($results);
        });

        $this->artisan('warden:audit --silent')
            ->assertExitCode(1);
    }

    public function testAuditCommandWithForceOption(): void
    {
        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock): void {
            $mock->shouldReceive('addAudit')->andReturnSelf();
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->artisan('warden:audit --force --silent')
            ->assertExitCode(0);
    }

    public function testAuditCommandWithJsonOutput(): void
    {
        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock): void {
            $mock->shouldReceive('addAudit')->andReturnSelf();
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->artisan('warden:audit --output=json')
            ->expectsOutputToContain('"vulnerabilities_found"')
            ->assertExitCode(0);
    }
}
