<?php

namespace Dgtlss\Warden\Services;

use Illuminate\Support\Facades\Cache;
use Carbon\Carbon;

class AuditCacheService
{
    protected string $cachePrefix = 'warden:audit:';
    protected int $cacheDuration;

    public function __construct()
    {
        $this->cacheDuration = config('warden.cache.duration', 3600); // Default 1 hour
    }

    /**
     * Check if an audit has been recently run.
     *
     * @param string $auditName
     * @return bool
     */
    public function hasRecentAudit(string $auditName): bool
    {
        return Cache::has($this->getCacheKey($auditName));
    }

    /**
     * Get cached audit result.
     *
     * @param string $auditName
     * @return array<array<string, mixed>>|null
     */
    public function getCachedResult(string $auditName): ?array
    {
        return Cache::get($this->getCacheKey($auditName));
    }

    /**
     * Store audit result in cache.
     *
     * @param string $auditName
     * @param array $result
     * @return void
     */
    public function storeResult(string $auditName, array $result): void
    {
        Cache::put(
            $this->getCacheKey($auditName),
            [
                'result' => $result,
                'timestamp' => Carbon::now()->toIso8601String(),
                'cached' => true
            ],
            $this->cacheDuration
        );
    }

    /**
     * Clear cached audit results.
     *
     * @param string|null $auditName
     * @return void
     */
    public function clearCache(?string $auditName = null): void
    {
        if ($auditName) {
            Cache::forget($this->getCacheKey($auditName));
        } else {
            // Clear all Warden audit cache
            Cache::flush(); // Note: In production, you might want to use tags instead
        }
    }

    /**
     * Get the cache key for an audit.
     *
     * @param string $auditName
     * @return string
     */
    protected function getCacheKey(string $auditName): string
    {
        return $this->cachePrefix . md5($auditName);
    }

    /**
     * Get time until next audit is allowed.
     *
     * @param string $auditName
     * @return int|null Seconds until next audit, null if not cached
     */
    public function getTimeUntilNextAudit(string $auditName): ?int
    {
        $cached = $this->getCachedResult($auditName);
        if (!$cached || !isset($cached['timestamp'])) {
            return null;
        }

        $cachedAt = Carbon::parse($cached['timestamp']);
        $expiresAt = $cachedAt->addSeconds($this->cacheDuration);
        
        return (int) max(0, $expiresAt->diffInSeconds(Carbon::now()));
    }
} 