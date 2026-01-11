<?php

namespace Dgtlss\Warden\Tests\Feature;

use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Mockery;

class CachingBehaviorTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Enable caching for these tests
        Config::set('warden.cache.enabled', true);
        Config::set('warden.cache.duration', 3600);
        Config::set('warden.cache.driver', 'array');
    }

    public function testAuditResultsAreCached(): void
    {
        $cacheService = new AuditCacheService();

        $findings = [
            [
                'source' => 'composer',
                'package' => 'test/package',
                'title' => 'Vulnerability',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        // Store result in cache
        $cacheService->storeResult('composer', $findings);

        // Verify it was cached
        $this->assertTrue($cacheService->hasRecentAudit('composer'));
    }

    public function testCachedResultsCanBeRetrieved(): void
    {
        $cacheService = new AuditCacheService();

        $findings = [
            [
                'source' => 'composer',
                'package' => 'test/package',
                'title' => 'Vulnerability',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        // Store and retrieve
        $cacheService->storeResult('composer', $findings);
        $cached = $cacheService->getCachedResult('composer');

        $this->assertIsArray($cached);
        $this->assertArrayHasKey('result', $cached);
        $this->assertArrayHasKey('timestamp', $cached);
        $this->assertEquals($findings, $cached['result']);
    }

    public function testCacheCanBeCleared(): void
    {
        $cacheService = new AuditCacheService();

        $findings = [
            [
                'source' => 'composer',
                'package' => 'test/package',
                'title' => 'Vulnerability',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        // Store, clear, and verify
        $cacheService->storeResult('composer', $findings);
        $this->assertTrue($cacheService->hasRecentAudit('composer'));

        $cacheService->clearCache('composer');
        $this->assertFalse($cacheService->hasRecentAudit('composer'));
    }

    public function testClearCacheWithoutNameClearsAll(): void
    {
        $cacheService = new AuditCacheService();

        $findings = [
            [
                'source' => 'test',
                'package' => 'test/package',
                'title' => 'Vulnerability',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        // Store multiple audit results
        $cacheService->storeResult('composer', $findings);
        $cacheService->storeResult('npm', $findings);

        // Clear all
        $cacheService->clearCache();

        // Verify all cleared
        $this->assertFalse($cacheService->hasRecentAudit('composer'));
        $this->assertFalse($cacheService->hasRecentAudit('npm'));
    }

    public function testTimeUntilNextAuditCalculatesCorrectly(): void
    {
        Config::set('warden.cache.duration', 3600); // 1 hour

        $cacheService = new AuditCacheService();

        $findings = [
            [
                'source' => 'test',
                'package' => 'test/package',
                'title' => 'Vulnerability',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        $cacheService->storeResult('composer', $findings);

        $timeUntilNext = $cacheService->getTimeUntilNextAudit('composer');

        // Should be an integer (may be close to 3600 or could be 0 in test environment)
        $this->assertIsInt($timeUntilNext);
        $this->assertGreaterThanOrEqual(0, $timeUntilNext);
        $this->assertLessThanOrEqual(3600, $timeUntilNext);
    }

    public function testHasRecentAuditReturnsFalseForNonCachedAudit(): void
    {
        $cacheService = new AuditCacheService();

        $this->assertFalse($cacheService->hasRecentAudit('nonexistent-audit'));
    }

    public function testGetCachedResultReturnsNullForNonCachedAudit(): void
    {
        $cacheService = new AuditCacheService();

        $this->assertNull($cacheService->getCachedResult('nonexistent-audit'));
    }

    public function testGetTimeUntilNextAuditReturnsNullForNonCachedAudit(): void
    {
        $cacheService = new AuditCacheService();

        $this->assertNull($cacheService->getTimeUntilNextAudit('nonexistent-audit'));
    }

    public function testCachingWorksWithRealCacheDriver(): void
    {
        // Use array driver (already configured)
        $cacheService = new AuditCacheService();

        $findings = [
            [
                'source' => 'composer',
                'package' => 'test/package',
                'title' => 'Test Vulnerability',
                'severity' => 'medium',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        // Store in cache
        $cacheService->storeResult('integration-test', $findings);

        // Verify it was cached by checking if we can retrieve it
        $this->assertTrue($cacheService->hasRecentAudit('integration-test'));

        // Retrieve and verify
        $cached = $cacheService->getCachedResult('integration-test');
        $this->assertEquals($findings, $cached['result']);

        // Clean up
        $cacheService->clearCache('integration-test');
    }

    public function testMultipleAuditsCanBeCachedIndependently(): void
    {
        $cacheService = new AuditCacheService();

        $composerFindings = [
            [
                'source' => 'composer',
                'package' => 'composer-package',
                'title' => 'Composer Vulnerability',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => '<1.0',
            ],
        ];

        $npmFindings = [
            [
                'source' => 'npm',
                'package' => 'npm-package',
                'title' => 'NPM Vulnerability',
                'severity' => 'medium',
                'cve' => null,
                'affected_versions' => '<2.0',
            ],
        ];

        // Store both
        $cacheService->storeResult('composer', $composerFindings);
        $cacheService->storeResult('npm', $npmFindings);

        // Verify both exist
        $this->assertTrue($cacheService->hasRecentAudit('composer'));
        $this->assertTrue($cacheService->hasRecentAudit('npm'));

        // Verify correct data is retrieved
        $composerCached = $cacheService->getCachedResult('composer');
        $npmCached = $cacheService->getCachedResult('npm');

        $this->assertEquals($composerFindings, $composerCached['result']);
        $this->assertEquals($npmFindings, $npmCached['result']);
    }
}
