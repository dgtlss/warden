<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Dgtlss\Warden\Services\IncrementalAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;

class IncrementalAuditServiceTest extends TestCase
{
    private IncrementalAuditService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new IncrementalAuditService();
        Cache::flush();
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    public function testIsEnabledReturnsFalseByDefault(): void
    {
        config(['warden.incremental.enabled' => false]);

        $this->assertFalse($this->service->isEnabled());
    }

    public function testIsEnabledReturnsTrueWhenEnabled(): void
    {
        config(['warden.incremental.enabled' => true]);

        $this->assertTrue($this->service->isEnabled());
    }

    public function testHasLockfileChangedReturnsTrueWhenNoCacheExists(): void
    {
        $this->assertTrue($this->service->hasLockfileChanged('composer'));
    }

    public function testHasLockfileChangedReturnsTrueWhenLockfileDoesNotExist(): void
    {
        $this->assertTrue($this->service->hasLockfileChanged('nonexistent'));
    }

    public function testCacheLockfileStoresCacheData(): void
    {
        $composerLockPath = base_path('composer.lock');

        if (!File::exists($composerLockPath)) {
            $this->markTestSkipped('composer.lock does not exist');
        }

        $this->service->cacheLockfile('composer');

        $this->assertFalse($this->service->hasLockfileChanged('composer'));
    }

    public function testClearCacheRemovesCachedData(): void
    {
        $composerLockPath = base_path('composer.lock');

        if (!File::exists($composerLockPath)) {
            $this->markTestSkipped('composer.lock does not exist');
        }

        $this->service->cacheLockfile('composer');
        $this->assertFalse($this->service->hasLockfileChanged('composer'));

        $this->service->clearCache('composer');
        $this->assertTrue($this->service->hasLockfileChanged('composer'));
    }

    public function testClearAllCachesClearsBothTypes(): void
    {
        $composerLockPath = base_path('composer.lock');

        if (!File::exists($composerLockPath)) {
            $this->markTestSkipped('composer.lock does not exist');
        }

        $this->service->cacheLockfile('composer');
        $this->service->clearAllCaches();

        $this->assertTrue($this->service->hasLockfileChanged('composer'));
    }

    public function testGetChangedPackagesReturnsEmptyArrayWhenNoLockfile(): void
    {
        $changes = $this->service->getChangedPackages('nonexistent');

        $this->assertIsArray($changes);
        $this->assertEmpty($changes);
    }

    public function testGetChangedPackagesReturnsAllAsAddedWhenNoCacheExists(): void
    {
        $composerLockPath = base_path('composer.lock');

        if (!File::exists($composerLockPath)) {
            $this->markTestSkipped('composer.lock does not exist');
        }

        $changes = $this->service->getChangedPackages('composer');

        $this->assertIsArray($changes);

        if (!empty($changes)) {
            $firstChange = reset($changes);
            $this->assertEquals('added', $firstChange['status']);
            $this->assertNull($firstChange['old_version']);
            $this->assertNotNull($firstChange['new_version']);
        }
    }

    public function testGetChangedPackagesReturnsEmptyWhenNoChanges(): void
    {
        $composerLockPath = base_path('composer.lock');

        if (!File::exists($composerLockPath)) {
            $this->markTestSkipped('composer.lock does not exist');
        }

        $this->service->cacheLockfile('composer');
        $changes = $this->service->getChangedPackages('composer');

        $this->assertIsArray($changes);
        $this->assertEmpty($changes);
    }

    public function testCacheLockfileDoesNothingForNonexistentFile(): void
    {
        $this->service->cacheLockfile('nonexistent');

        $this->assertTrue($this->service->hasLockfileChanged('nonexistent'));
    }
}
