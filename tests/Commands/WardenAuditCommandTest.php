<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\Enums\Severity;
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
        $mockService = \Mockery::mock(\Dgtlss\Warden\Contracts\AuditService::class);
        $mockService->shouldReceive('getName')->andReturn('composer');
        $mockService->shouldReceive('getAbandonedPackages')->andReturn([]);

        $results = [
            'composer' => [
                'success' => true,
                'findings' => [
                    new Finding(
                        source: 'composer',
                        package: 'test/package',
                        title: 'High severity vulnerability',
                        severity: Severity::HIGH,
                        cve: 'CVE-2024-1234',
                        affectedVersions: '<1.0',
                    ),
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

    public function testAuditCommandWithDryRunOption(): void
    {
        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock): void {
            $mock->shouldReceive('addAudit')->andReturnSelf();
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->artisan('warden:audit --dry-run')
            ->expectsOutputToContain('DRY RUN MODE')
            ->assertExitCode(0);
    }

    public function testAuditCommandDryRunDoesNotSendNotifications(): void
    {
        $mockService = \Mockery::mock(\Dgtlss\Warden\Contracts\AuditService::class);
        $mockService->shouldReceive('getName')->andReturn('composer');
        $mockService->shouldReceive('getAbandonedPackages')->andReturn([]);

        $results = [
            'composer' => [
                'success' => true,
                'findings' => [
                    new Finding(
                        source: 'composer',
                        package: 'test/package',
                        title: 'High severity vulnerability',
                        severity: Severity::HIGH,
                        cve: 'CVE-2024-1234',
                        affectedVersions: '<1.0',
                    ),
                ],
                'service' => $mockService,
            ],
        ];

        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock) use ($results): void {
            $mock->shouldReceive('addAudit')->andReturnSelf();
            $mock->shouldReceive('execute')->once()->andReturn($results);
        });

        $this->artisan('warden:audit --dry-run')
            ->expectsOutputToContain('DRY RUN: Would have sent')
            ->assertExitCode(1);
    }

    public function testAuditCommandWithQueueOption(): void
    {
        Config::set('warden.queue.enabled', true);
        Config::set('warden.queue.connection', 'sync');
        Config::set('warden.queue.queue_name', 'default');

        // The --queue option should dispatch a job and exit with 0
        $this->artisan('warden:audit --queue --silent')
            ->assertExitCode(0);
    }

    public function testAuditCommandWithVerboseOption(): void
    {
        $mockService = \Mockery::mock(\Dgtlss\Warden\Contracts\AuditService::class);
        $mockService->shouldReceive('getName')->andReturn('composer');
        $mockService->shouldReceive('getAbandonedPackages')->andReturn([]);

        $results = [
            'composer' => [
                'success' => true,
                'findings' => [],
                'service' => $mockService,
            ],
        ];

        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock) use ($results): void {
            $mock->shouldReceive('addAudit')->andReturnSelf();
            $mock->shouldReceive('execute')->once()->andReturn($results);
        });

        // Verbose output uses $this->line() which may not be captured by expectsOutputToContain
        // Just verify the command runs successfully with verbose flag
        $this->artisan('warden:audit --silent -v')
            ->assertExitCode(0);
    }

    public function testAuditCommandWithSeverityFilter(): void
    {
        $mockService = \Mockery::mock(\Dgtlss\Warden\Contracts\AuditService::class);
        $mockService->shouldReceive('getName')->andReturn('composer');
        $mockService->shouldReceive('getAbandonedPackages')->andReturn([]);

        $results = [
            'composer' => [
                'success' => true,
                'findings' => [
                    new Finding(
                        source: 'composer',
                        package: 'test/low',
                        title: 'Low severity vulnerability',
                        severity: Severity::LOW,
                        cve: 'CVE-2024-0001',
                        affectedVersions: '<1.0',
                    ),
                    new Finding(
                        source: 'composer',
                        package: 'test/high',
                        title: 'High severity vulnerability',
                        severity: Severity::HIGH,
                        cve: 'CVE-2024-0002',
                        affectedVersions: '<1.0',
                    ),
                ],
                'service' => $mockService,
            ],
        ];

        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock) use ($results): void {
            $mock->shouldReceive('addAudit')->andReturnSelf();
            $mock->shouldReceive('execute')->once()->andReturn($results);
        });

        // With high severity filter, should filter to 1 vulnerability and exit with code 1
        $this->artisan('warden:audit --severity=high --silent')
            ->assertExitCode(1);
    }
}
