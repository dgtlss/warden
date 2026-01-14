<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Dgtlss\Warden\Services\IncrementalAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;

class IncrementalAuditServiceTest extends TestCase
{
    private IncrementalAuditService $service;
    private string $composerLockPath;
    private string $packageLockPath;
    private ?string $originalComposerLock = null;
    private ?string $originalPackageLock = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new IncrementalAuditService();
        Cache::flush();
        $this->composerLockPath = base_path('composer.lock');
        $this->packageLockPath = base_path('package-lock.json');

        if (File::exists($this->composerLockPath)) {
            $this->originalComposerLock = File::get($this->composerLockPath);
        } else {
            $this->originalComposerLock = null;
        }

        if (File::exists($this->packageLockPath)) {
            $this->originalPackageLock = File::get($this->packageLockPath);
        } else {
            $this->originalPackageLock = null;
        }

        $fixture = $this->getFixture('composer-lock.json');
        File::put($this->composerLockPath, $fixture);
        File::put($this->packageLockPath, $this->getFixture('package-lock.json'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        if ($this->originalComposerLock !== null) {
            File::put($this->composerLockPath, $this->originalComposerLock);
        } elseif (File::exists($this->composerLockPath)) {
            File::delete($this->composerLockPath);
        }
        if ($this->originalPackageLock !== null) {
            File::put($this->packageLockPath, $this->originalPackageLock);
        } elseif (File::exists($this->packageLockPath)) {
            File::delete($this->packageLockPath);
        }
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
        $this->service->cacheLockfile('composer');

        $this->assertFalse($this->service->hasLockfileChanged('composer'));
    }

    public function testClearCacheRemovesCachedData(): void
    {
        $this->service->cacheLockfile('composer');
        $this->assertFalse($this->service->hasLockfileChanged('composer'));

        $this->service->clearCache('composer');
        $this->assertTrue($this->service->hasLockfileChanged('composer'));
    }

    public function testClearAllCachesClearsBothTypes(): void
    {
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

    public function testCacheLockfileStoresNpmPackages(): void
    {
        $this->service->cacheLockfile('npm');

        $this->assertFalse($this->service->hasLockfileChanged('npm'));
    }

    public function testGetChangedPackagesDetectsUpdatedNpmPackage(): void
    {
        $this->service->cacheLockfile('npm');

        $updatedLock = [
            'name' => 'test-app',
            'version' => '1.0.0',
            'lockfileVersion' => 2,
            'packages' => [
                '' => [
                    'name' => 'test-app',
                    'version' => '1.0.0',
                ],
                'node_modules/lodash' => [
                    'version' => '4.17.21',
                ],
            ],
        ];

        File::put($this->packageLockPath, json_encode($updatedLock));

        $changes = $this->service->getChangedPackages('npm');

        $this->assertArrayHasKey('lodash', $changes);
        $this->assertEquals('updated', $changes['lodash']['status']);
        $this->assertEquals('4.17.20', $changes['lodash']['old_version']);
        $this->assertEquals('4.17.21', $changes['lodash']['new_version']);
    }
}
