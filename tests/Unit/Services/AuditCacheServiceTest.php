<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Carbon\Carbon;

class AuditCacheServiceTest extends TestCase
{
    private AuditCacheService $service;

    protected function setUp(): void
    {
        parent::setUp();

        // Enable caching for these tests
        Config::set('warden.cache.enabled', true);
        Config::set('warden.cache.duration', 3600);

        $this->service = new AuditCacheService();
    }

    public function testHasRecentAuditReturnsFalseWhenNotCached(): void
    {
        $this->assertFalse($this->service->hasRecentAudit('composer'));
    }

    public function testHasRecentAuditReturnsTrueWhenCached(): void
    {
        $result = [['package' => 'test/package', 'severity' => 'high']];

        $this->service->storeResult('composer', $result);

        $this->assertTrue($this->service->hasRecentAudit('composer'));
    }

    public function testStoreResultCachesData(): void
    {
        $result = [
            [
                'package' => 'symfony/http-kernel',
                'title' => 'Security vulnerability',
                'severity' => 'high',
                'cve' => 'CVE-2024-1234',
            ]
        ];

        $this->service->storeResult('composer', $result);

        $this->assertTrue($this->service->hasRecentAudit('composer'));

        $cached = $this->service->getCachedResult('composer');

        $this->assertNotNull($cached);
        $this->assertIsArray($cached);
        $this->assertArrayHasKey('result', $cached);
        $this->assertArrayHasKey('timestamp', $cached);
        $this->assertArrayHasKey('cached', $cached);
        $this->assertTrue($cached['cached']);
        $this->assertEquals($result, $cached['result']);
    }

    public function testGetCachedResultReturnsNullWhenNotCached(): void
    {
        $result = $this->service->getCachedResult('nonexistent');

        $this->assertNull($result);
    }

    public function testGetCachedResultReturnsDataWhenCached(): void
    {
        $result = [
            ['package' => 'laravel/framework', 'severity' => 'medium']
        ];

        $this->service->storeResult('composer', $result);

        $cached = $this->service->getCachedResult('composer');

        $this->assertNotNull($cached);
        $this->assertEquals($result, $cached['result']);
        $this->assertIsString($cached['timestamp']);
        $this->assertTrue($cached['cached']);
    }

    public function testClearCacheRemovesSpecificAudit(): void
    {
        $this->service->storeResult('composer', []);
        $this->service->storeResult('npm', []);

        $this->assertTrue($this->service->hasRecentAudit('composer'));
        $this->assertTrue($this->service->hasRecentAudit('npm'));

        $this->service->clearCache('composer');

        $this->assertFalse($this->service->hasRecentAudit('composer'));
        $this->assertTrue($this->service->hasRecentAudit('npm'));
    }

    public function testClearCacheRemovesAllAuditsWhenNoNameProvided(): void
    {
        $this->service->storeResult('composer', []);
        $this->service->storeResult('npm', []);

        $this->assertTrue($this->service->hasRecentAudit('composer'));
        $this->assertTrue($this->service->hasRecentAudit('npm'));

        $this->service->clearCache();

        $this->assertFalse($this->service->hasRecentAudit('composer'));
        $this->assertFalse($this->service->hasRecentAudit('npm'));
    }

    public function testGetTimeUntilNextAuditReturnsNullWhenNotCached(): void
    {
        $timeUntil = $this->service->getTimeUntilNextAudit('composer');

        $this->assertNull($timeUntil);
    }

    public function testGetTimeUntilNextAuditReturnsSeconds(): void
    {
        $this->service->storeResult('composer', []);

        // Immediately after storing, there should be time remaining
        $timeUntil = $this->service->getTimeUntilNextAudit('composer');

        $this->assertIsInt($timeUntil);
        // Time should be between 0 and cache duration (3600)
        $this->assertGreaterThanOrEqual(0, $timeUntil);
        $this->assertLessThanOrEqual(3600, $timeUntil);
    }

    public function testGetTimeUntilNextAuditCalculatesCorrectly(): void
    {
        // Store a result
        $this->service->storeResult('composer', []);

        // Get the cached result to check timestamp
        $cached = $this->service->getCachedResult('composer');
        $this->assertNotNull($cached);

        // Parse timestamp and calculate expected time until expiration
        $cachedAt = Carbon::parse($cached['timestamp']);
        $expiresAt = $cachedAt->copy()->addSeconds(3600);
        $expectedTime = (int) max(0, $expiresAt->diffInSeconds(Carbon::now()));

        $actualTime = $this->service->getTimeUntilNextAudit('composer');

        // Allow 2 second difference due to test execution time
        $this->assertEqualsWithDelta($expectedTime, $actualTime, 2);
    }

    public function testMultipleAuditsCanBeCachedIndependently(): void
    {
        $composerResult = [['package' => 'symfony/http-kernel', 'severity' => 'high']];
        $npmResult = [['package' => 'lodash', 'severity' => 'medium']];

        $this->service->storeResult('composer', $composerResult);
        $this->service->storeResult('npm', $npmResult);

        $cachedComposer = $this->service->getCachedResult('composer');
        $cachedNpm = $this->service->getCachedResult('npm');

        $this->assertNotNull($cachedComposer);
        $this->assertNotNull($cachedNpm);
        $this->assertEquals($composerResult, $cachedComposer['result']);
        $this->assertEquals($npmResult, $cachedNpm['result']);
    }

    public function testStoreResultWithEmptyArray(): void
    {
        $this->service->storeResult('composer', []);

        $cached = $this->service->getCachedResult('composer');

        $this->assertNotNull($cached);
        $this->assertIsArray($cached['result']);
        $this->assertEmpty($cached['result']);
    }

    public function testCacheKeyIsHashed(): void
    {
        // Test that different audit names produce different cache keys
        $this->service->storeResult('composer', [['finding' => 'one']]);
        $this->service->storeResult('npm', [['finding' => 'two']]);

        $composerCached = $this->service->getCachedResult('composer');
        $npmCached = $this->service->getCachedResult('npm');

        $this->assertNotNull($composerCached);
        $this->assertNotNull($npmCached);
        $this->assertNotEquals($composerCached['result'], $npmCached['result']);
    }

    public function testTimestampIsIso8601Format(): void
    {
        $this->service->storeResult('composer', []);

        $cached = $this->service->getCachedResult('composer');

        $this->assertNotNull($cached);
        $this->assertIsString($cached['timestamp']);

        // Verify it can be parsed back to a Carbon instance
        $timestamp = Carbon::parse($cached['timestamp']);
        $this->assertInstanceOf(Carbon::class, $timestamp);
    }
}
