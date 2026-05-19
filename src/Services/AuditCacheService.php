<?php

namespace Dgtlss\Warden\Services;

use Illuminate\Support\Facades\Cache;
use Carbon\Carbon;

class AuditCacheService
{
    /**
     * Stores all active cache keys so they can be cleared safely without flushing the app cache.
     */
    private const MANIFEST_KEY = 'warden:audit:manifest';

    protected string $cachePrefix = 'warden:audit:';

    protected int $cacheDuration;

    public function __construct()
    {
        $this->cacheDuration = config('warden.cache.duration', 3600); // Default 1 hour
    }

    /**
     * Check if an audit has been recently run.
     */
    public function hasRecentAudit(string $auditName, ?string $signature = null): bool
    {
        try {
            return Cache::has($this->getCacheKey($auditName, $signature));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Get cached audit result.
     *
     * @return array<array<string, mixed>>|null
     */
    /**
     * @return array{result: array<array<string, mixed>>, timestamp: string, cached: bool, signature?: string|null, metadata?: array<string, mixed>}|null
     */
    public function getCachedResult(string $auditName, ?string $signature = null): ?array
    {
        try {
            $cached = Cache::get($this->getCacheKey($auditName, $signature));
        } catch (\Throwable) {
            return null;
        }

        if (!is_array($cached)) {
            return null;
        }

        if (!isset($cached['timestamp']) || !is_string($cached['timestamp'])) {
            return null;
        }

        if (!isset($cached['result']) || !is_array($cached['result'])) {
            return null;
        }

        $cached['cached'] = (bool) ($cached['cached'] ?? false);

        return $cached;
    }

    /**
     * Store audit result in cache.
     */
    public function storeResult(string $auditName, array $result, ?string $signature = null, array $metadata = []): void
    {
        $cacheKey = $this->getCacheKey($auditName, $signature);

        try {
            Cache::put(
                $cacheKey,
                [
                    'result' => $result,
                    'timestamp' => Carbon::now()->toIso8601String(),
                    'cached' => true,
                    'signature' => $signature,
                    'metadata' => $metadata,
                ],
                $this->cacheDuration
            );

            $this->trackCacheKey($cacheKey);
        } catch (\Throwable) {
            // Fail open when the underlying cache store is unavailable.
        }
    }

    /**
     * Clear cached audit results.
     */
    public function clearCache(?string $auditName = null): void
    {
        if ($auditName) {
            $manifest = $this->manifest();
            foreach ($manifest as $cacheKey) {
                if (str_contains($cacheKey, md5($auditName))) {
                    try {
                        Cache::forget($cacheKey);
                    } catch (\Throwable) {
                        // Ignore cache store failures during cleanup.
                    }
                }
            }

            $this->storeManifest(array_values(array_filter(
                $manifest,
                static fn (string $cacheKey): bool => !str_contains($cacheKey, md5($auditName))
            )));
        } else {
            foreach ($this->manifest() as $cacheKey) {
                try {
                    Cache::forget($cacheKey);
                } catch (\Throwable) {
                    // Ignore cache store failures during cleanup.
                }
            }

            $this->storeManifest([]);
        }
    }

    /**
     * Get the cache key for an audit.
     */
    protected function getCacheKey(string $auditName, ?string $signature = null): string
    {
        return $this->cachePrefix . md5($auditName . '|' . ($signature ?? 'default'));
    }

    /**
     * Get time until next audit is allowed.
     *
     * @return int|null Seconds until next audit, null if not cached
     */
    public function getTimeUntilNextAudit(string $auditName, ?string $signature = null): ?int
    {
        $cached = $this->getCachedResult($auditName, $signature);
        if ($cached === null) {
            return null;
        }

        $cachedAt = Carbon::parse($cached['timestamp']);
        $expiresAt = $cachedAt->addSeconds($this->cacheDuration);

        return (int) max(0, $expiresAt->diffInSeconds(Carbon::now()));
    }

    protected function trackCacheKey(string $cacheKey): void
    {
        $manifest = $this->manifest();
        $manifest[] = $cacheKey;

        $this->storeManifest(array_values(array_unique($manifest)));
    }

    /**
     * @return array<int, string>
     */
    protected function manifest(): array
    {
        try {
            $manifest = Cache::get(self::MANIFEST_KEY, []);
        } catch (\Throwable) {
            return [];
        }

        if (!is_array($manifest)) {
            return [];
        }

        return array_values(array_filter($manifest, static fn ($value): bool => is_string($value)));
    }

    /**
     * @param array<int, string> $manifest
     */
    protected function storeManifest(array $manifest): void
    {
        try {
            Cache::forever(self::MANIFEST_KEY, $manifest);
        } catch (\Throwable) {
            // Ignore cache store failures during manifest writes.
        }
    }
}
