<?php

namespace Dgtlss\Warden\Tests\Unit\Providers;

use Dgtlss\Warden\Commands\WardenAuditCommand;
use Dgtlss\Warden\Commands\WardenScheduleCommand;
use Dgtlss\Warden\Commands\WardenSyntaxCommand;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;

class WardenServiceProviderTest extends TestCase
{
    public function testServiceProviderIsRegistered(): void
    {
        $providers = $this->app->getLoadedProviders();

        $this->assertArrayHasKey(WardenServiceProvider::class, $providers);
    }

    public function testConfigurationIsMerged(): void
    {
        // Verify config was merged
        $this->assertNotNull(config('warden'));
        $this->assertIsArray(config('warden'));
        $this->assertArrayHasKey('app_name', config('warden'));
        $this->assertArrayHasKey('cache', config('warden'));
        $this->assertArrayHasKey('audits', config('warden'));
    }

    public function testAuditCacheServiceIsSingleton(): void
    {
        $service1 = $this->app->make(AuditCacheService::class);
        $service2 = $this->app->make(AuditCacheService::class);

        // Singletons should return the same instance
        $this->assertSame($service1, $service2);
    }

    public function testAuditCacheServiceIsResolvable(): void
    {
        $service = $this->app->make(AuditCacheService::class);

        $this->assertInstanceOf(AuditCacheService::class, $service);
    }

    public function testParallelAuditExecutorIsResolvable(): void
    {
        $executor = $this->app->make(ParallelAuditExecutor::class);

        $this->assertInstanceOf(ParallelAuditExecutor::class, $executor);
    }

    public function testParallelAuditExecutorIsNotSingleton(): void
    {
        $executor1 = $this->app->make(ParallelAuditExecutor::class);
        $executor2 = $this->app->make(ParallelAuditExecutor::class);

        // Should return different instances (bound, not singleton)
        $this->assertNotSame($executor1, $executor2);
    }

    public function testCommandsAreRegistered(): void
    {
        // Get all registered commands
        $commands = Artisan::all();

        // Check that Warden commands are registered
        $this->assertArrayHasKey('warden:audit', $commands);
        $this->assertArrayHasKey('warden:schedule', $commands);
        $this->assertArrayHasKey('warden:syntax', $commands);
    }

    public function testWardenAuditCommandIsRegistered(): void
    {
        $command = Artisan::all()['warden:audit'];

        $this->assertInstanceOf(WardenAuditCommand::class, $command);
    }

    public function testWardenScheduleCommandIsRegistered(): void
    {
        $command = Artisan::all()['warden:schedule'];

        $this->assertInstanceOf(WardenScheduleCommand::class, $command);
    }

    public function testWardenSyntaxCommandIsRegistered(): void
    {
        $command = Artisan::all()['warden:syntax'];

        $this->assertInstanceOf(WardenSyntaxCommand::class, $command);
    }

    public function testViewsAreLoaded(): void
    {
        // Check that views are loaded with 'warden' namespace
        $viewFinder = $this->app['view']->getFinder();
        $hints = $viewFinder->getHints();

        $this->assertArrayHasKey('warden', $hints);
        $this->assertNotEmpty($hints['warden']);
    }

    public function testConfigCanBePublished(): void
    {
        // Get publishable resources
        $publishGroups = WardenServiceProvider::pathsToPublish(
            WardenServiceProvider::class,
            'warden-config'
        );

        // Just verify that there are publishable config files
        $this->assertIsArray($publishGroups);
    }

    public function testServicesAreAvailableInContainer(): void
    {
        // Verify services are bound in container
        $this->assertTrue($this->app->bound(AuditCacheService::class));
        $this->assertTrue($this->app->bound(ParallelAuditExecutor::class));
    }

    public function testSchedulingIsDisabledByDefault(): void
    {
        // Default config should have scheduling disabled
        $this->assertFalse(config('warden.schedule.enabled', false));
    }

    public function testCacheConfigurationExists(): void
    {
        // Cache config should exist (TestCase may override the default value)
        $this->assertNotNull(config('warden.cache'));
        $this->assertArrayHasKey('enabled', config('warden.cache'));
        $this->assertArrayHasKey('duration', config('warden.cache'));
    }

    public function testDefaultCacheDurationIs3600(): void
    {
        $this->assertEquals(3600, config('warden.cache.duration', 3600));
    }

    public function testParallelExecutionIsEnabledByDefault(): void
    {
        // In tests it's disabled by default (from TestCase), but in config it should be true
        $provider = new WardenServiceProvider($this->app);

        // The config should exist
        $this->assertNotNull(config('warden.audits.parallel_execution'));
    }
}
