<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Commands\WardenAuditCommand;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Services\AuditCacheService;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Mockery\MockInterface;

class WardenAuditCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    public function testCICDModeShowsCorrectMessage()
    {
        $result = $this->artisan('warden:audit');
        $result->expectsOutputToContain('Running CI/CD security audit...');
        // Just verify it runs without crashing - exit codes will vary in test environment
    }

    public function testFullModeUsesParallelExecution()
    {
        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock) {
            $mock->shouldReceive('addAudit')->times(4); // Core services
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->mock(AuditCacheService::class, function (MockInterface $mock) {
            $mock->shouldReceive('clearCache')->never();
        });

        $this->artisan('warden:audit --full')
            ->expectsOutputToContain('Warden Audit Version')
            ->assertExitCode(0);
    }

    public function testFullModeWithForceClearsCache()
    {
        $this->mock(ParallelAuditExecutor::class, function (MockInterface $mock) {
            $mock->shouldReceive('addAudit')->times(4); // Core services
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->mock(AuditCacheService::class, function (MockInterface $mock) {
            $mock->shouldReceive('clearCache')->once();
        });

        $this->artisan('warden:audit --full --force')
            ->expectsOutputToContain('Cache cleared.')
            ->assertExitCode(0);
    }

    public function testCommandSignatureIncludesFullFlag()
    {
        $command = $this->app->make(WardenAuditCommand::class);
        
        // Use reflection to access the protected signature property
        $reflection = new \ReflectionClass($command);
        $signatureProperty = $reflection->getProperty('signature');
        $signatureProperty->setAccessible(true);
        $signature = $signatureProperty->getValue($command);
        
        $this->assertStringContainsString('--full', $signature);
        $this->assertStringContainsString('Run comprehensive security audit with all checks', $signature);
    }

    public function testCICDModeWithJsonOutput()
    {
        $result = $this->artisan('warden:audit --output=json');
        $result->expectsOutputToContain('Running CI/CD security audit...');
        // Just verify it runs without crashing
    }

    public function testCICDModeWithSeverityFilter()
    {
        $result = $this->artisan('warden:audit --severity=high');
        $result->expectsOutputToContain('Running CI/CD security audit...');
        // Just verify it runs without crashing
    }
}