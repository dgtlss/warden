<?php

namespace Dgtlss\Warden\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;

/**
 * Service for incremental audits based on lockfile changes.
 */
class IncrementalAuditService
{
    /**
     * Cache key prefix for lockfile hashes.
     */
    private const CACHE_PREFIX = 'warden:lockfile:';

    /**
     * Default cache TTL in seconds (24 hours).
     */
    private const DEFAULT_CACHE_TTL = 86400;

    /**
     * Check if the lockfile for the given type has changed since the last audit.
     */
    public function hasLockfileChanged(string $type): bool
    {
        $lockfilePath = $this->getLockfilePath($type);

        if (!File::exists($lockfilePath)) {
            return true;
        }

        $currentHash = $this->calculateLockfileHash($lockfilePath);
        $cachedHash = $this->getCachedHash($type);

        if ($cachedHash === null) {
            return true;
        }

        return $currentHash !== $cachedHash;
    }

    /**
     * Get the packages that have changed since the last audit.
     *
     * @return array<string, array{old_version: string|null, new_version: string|null, status: string}>
     */
    public function getChangedPackages(string $type): array
    {
        $lockfilePath = $this->getLockfilePath($type);

        if (!File::exists($lockfilePath)) {
            return [];
        }

        $currentPackages = $this->parseLockfile($lockfilePath, $type);
        $cachedPackages = $this->getCachedPackages($type);

        if (empty($cachedPackages)) {
            $result = [];
            foreach ($currentPackages as $package => $version) {
                $result[$package] = [
                    'old_version' => null,
                    'new_version' => $version,
                    'status' => 'added',
                ];
            }

            return $result;
        }

        $changes = [];

        foreach ($currentPackages as $package => $version) {
            if (!isset($cachedPackages[$package])) {
                $changes[$package] = [
                    'old_version' => null,
                    'new_version' => $version,
                    'status' => 'added',
                ];
            } elseif ($cachedPackages[$package] !== $version) {
                $changes[$package] = [
                    'old_version' => $cachedPackages[$package],
                    'new_version' => $version,
                    'status' => 'updated',
                ];
            }
        }

        foreach ($cachedPackages as $package => $version) {
            if (!isset($currentPackages[$package])) {
                $changes[$package] = [
                    'old_version' => $version,
                    'new_version' => null,
                    'status' => 'removed',
                ];
            }
        }

        return $changes;
    }

    /**
     * Cache the current lockfile state.
     */
    public function cacheLockfile(string $type): void
    {
        $lockfilePath = $this->getLockfilePath($type);

        if (!File::exists($lockfilePath)) {
            return;
        }

        $hash = $this->calculateLockfileHash($lockfilePath);
        $packages = $this->parseLockfile($lockfilePath, $type);

        /** @var int $ttl */
        $ttl = config('warden.incremental.cache_ttl', self::DEFAULT_CACHE_TTL);

        Cache::put($this->getHashCacheKey($type), $hash, $ttl);
        Cache::put($this->getPackagesCacheKey($type), $packages, $ttl);
    }

    /**
     * Clear the cached lockfile state.
     */
    public function clearCache(string $type): void
    {
        Cache::forget($this->getHashCacheKey($type));
        Cache::forget($this->getPackagesCacheKey($type));
    }

    /**
     * Clear all cached lockfile states.
     */
    public function clearAllCaches(): void
    {
        $types = ['composer', 'npm'];

        foreach ($types as $type) {
            $this->clearCache($type);
        }
    }

    /**
     * Check if incremental audits are enabled.
     */
    public function isEnabled(): bool
    {
        /** @var bool $enabled */
        $enabled = config('warden.incremental.enabled', false);

        return $enabled;
    }

    /**
     * Get the path to the lockfile for the given type.
     */
    protected function getLockfilePath(string $type): string
    {
        return match (strtolower($type)) {
            'composer' => base_path('composer.lock'),
            'npm' => base_path('package-lock.json'),
            default => '',
        };
    }

    /**
     * Calculate a hash of the lockfile contents.
     */
    protected function calculateLockfileHash(string $path): string
    {
        if (!File::exists($path)) {
            return '';
        }

        $contents = File::get($path);

        return hash('sha256', $contents);
    }

    /**
     * Get the cached hash for the lockfile.
     */
    protected function getCachedHash(string $type): ?string
    {
        $cached = Cache::get($this->getHashCacheKey($type));

        return is_string($cached) ? $cached : null;
    }

    /**
     * Get the cached packages for the lockfile.
     *
     * @return array<string, string>
     */
    protected function getCachedPackages(string $type): array
    {
        $cached = Cache::get($this->getPackagesCacheKey($type));

        if (!is_array($cached)) {
            return [];
        }

        /** @var array<string, string> $result */
        $result = [];
        foreach ($cached as $key => $value) {
            if (is_string($key) && is_string($value)) {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     * Parse a lockfile and extract package versions.
     *
     * @return array<string, string>
     */
    protected function parseLockfile(string $path, string $type): array
    {
        if (!File::exists($path)) {
            return [];
        }

        $contents = File::get($path);
        $data = json_decode($contents, true);

        if (!is_array($data)) {
            return [];
        }

        /** @var array<string, mixed> $typedData */
        $typedData = $data;

        return match (strtolower($type)) {
            'composer' => $this->parseComposerLock($typedData),
            'npm' => $this->parseNpmLock($typedData),
            default => [],
        };
    }

    /**
     * Parse composer.lock file.
     *
     * @param array<string, mixed> $data
     * @return array<string, string>
     */
    protected function parseComposerLock(array $data): array
    {
        $packages = [];

        $sections = ['packages', 'packages-dev'];

        foreach ($sections as $section) {
            if (!isset($data[$section]) || !is_array($data[$section])) {
                continue;
            }

            foreach ($data[$section] as $package) {
                if (!is_array($package)) {
                    continue;
                }

                $name = $package['name'] ?? null;
                $version = $package['version'] ?? null;

                if (is_string($name) && is_string($version)) {
                    $packages[$name] = $version;
                }
            }
        }

        return $packages;
    }

    /**
     * Parse package-lock.json file (npm v7+ format).
     *
     * @param array<string, mixed> $data
     * @return array<string, string>
     */
    protected function parseNpmLock(array $data): array
    {
        $packages = [];

        if (isset($data['packages']) && is_array($data['packages'])) {
            foreach ($data['packages'] as $path => $info) {
                if (!is_string($path) || !is_array($info)) {
                    continue;
                }

                if ($path === '' || str_starts_with($path, 'node_modules/')) {
                    $name = $path === '' ? ($info['name'] ?? 'root') : substr($path, strlen('node_modules/'));
                    $version = $info['version'] ?? null;

                    if (is_string($name) && is_string($version)) {
                        $packages[$name] = $version;
                    }
                }
            }
        } elseif (isset($data['dependencies']) && is_array($data['dependencies'])) {
            foreach ($data['dependencies'] as $name => $info) {
                if (!is_string($name) || !is_array($info)) {
                    continue;
                }

                $version = $info['version'] ?? null;

                if (is_string($version)) {
                    $packages[$name] = $version;
                }
            }
        }

        return $packages;
    }

    /**
     * Get the cache key for the lockfile hash.
     */
    protected function getHashCacheKey(string $type): string
    {
        return self::CACHE_PREFIX . $type . ':hash';
    }

    /**
     * Get the cache key for the packages list.
     */
    protected function getPackagesCacheKey(string $type): string
    {
        return self::CACHE_PREFIX . $type . ':packages';
    }
}
