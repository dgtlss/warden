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
        $duration = config('warden.cache.duration', 3600);
        $this->cacheDuration = is_int($duration) ? $duration : 3600; // Default 1 hour
    }

    /**
     * Check if an audit has been recently run.
     */
    public function hasRecentAudit(string $auditName): bool
    {
        return Cache::has($this->getCacheKey($auditName));
    }

    /**
     * Get cached audit result.
     *
     * @return array{result: array<int, array<string, mixed>>, timestamp: string, cached: bool}|null
     */
    public function getCachedResult(string $auditName): ?array
    {
        $cached = Cache::get($this->getCacheKey($auditName));

        if (!is_array($cached)) {
            return null;
        }

        if (!isset($cached['timestamp']) || !is_string($cached['timestamp'])) {
            return null;
        }

        if (!isset($cached['result']) || !is_array($cached['result'])) {
            return null;
        }

        /** @var array<int, array<string, mixed>> $result */
        $result = $cached['result'];

        return [
            'result' => $result,
            'timestamp' => $cached['timestamp'],
            'cached' => (bool) ($cached['cached'] ?? false)
        ];
    }

    /**
     * Store audit result in cache.
     *
     * @param array<int, array<string, mixed>> $result
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
     */
    protected function getCacheKey(string $auditName): string
    {
        return $this->cachePrefix . md5($auditName);
    }

    /**
     * Get time until next audit is allowed.
     *
     * @return int|null Seconds until next audit, null if not cached
     */
    public function getTimeUntilNextAudit(string $auditName): ?int
    {
        $cached = $this->getCachedResult($auditName);
        if ($cached === null) {
            return null;
        }

        $cachedAt = Carbon::parse($cached['timestamp']);
        $expiresAt = $cachedAt->addSeconds($this->cacheDuration);

        return (int) max(0, $expiresAt->diffInSeconds(Carbon::now()));
    }
} 
