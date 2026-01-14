<?php

namespace Dgtlss\Warden\Services;

use Illuminate\Cache\RateLimiter;
use Illuminate\Support\Facades\RateLimiter as RateLimiterFacade;

/**
 * Rate limiter for audit operations to prevent abuse.
 */
class AuditRateLimiter
{
    /**
     * The cache key prefix for rate limiting.
     */
    private const KEY_PREFIX = 'warden:audit:';

    /**
     * Default maximum attempts per decay period.
     */
    private const DEFAULT_MAX_ATTEMPTS = 10;

    /**
     * Default decay time in minutes.
     */
    private const DEFAULT_DECAY_MINUTES = 60;

    public function __construct(
        private readonly int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS,
        private readonly int $decayMinutes = self::DEFAULT_DECAY_MINUTES,
    ) {
    }

    /**
     * Create an instance from config.
     */
    public static function fromConfig(): self
    {
        /** @var int $maxAttempts */
        $maxAttempts = config('warden.rate_limit.max_attempts', self::DEFAULT_MAX_ATTEMPTS);

        /** @var int $decayMinutes */
        $decayMinutes = config('warden.rate_limit.decay_minutes', self::DEFAULT_DECAY_MINUTES);

        return new self($maxAttempts, $decayMinutes);
    }

    /**
     * Check if rate limiting is enabled.
     */
    public function isEnabled(): bool
    {
        /** @var bool $enabled */
        $enabled = config('warden.rate_limit.enabled', false);

        return $enabled;
    }

    /**
     * Attempt to perform an audit and record the hit.
     * Returns true if the attempt is allowed, false if rate limited.
     */
    public function attempt(string $key): bool
    {
        $cacheKey = $this->getCacheKey($key);

        if ($this->tooManyAttempts($key)) {
            return false;
        }

        $this->hit($key);

        return true;
    }

    /**
     * Record a hit for the given key.
     */
    public function hit(string $key): void
    {
        $cacheKey = $this->getCacheKey($key);

        RateLimiterFacade::hit($cacheKey, $this->decayMinutes * 60);
    }

    /**
     * Check if there are too many attempts for the given key.
     */
    public function tooManyAttempts(string $key): bool
    {
        $cacheKey = $this->getCacheKey($key);

        return RateLimiterFacade::tooManyAttempts($cacheKey, $this->maxAttempts);
    }

    /**
     * Get the number of remaining attempts for the given key.
     */
    public function remainingAttempts(string $key): int
    {
        $cacheKey = $this->getCacheKey($key);

        return RateLimiterFacade::remaining($cacheKey, $this->maxAttempts);
    }

    /**
     * Get the number of seconds until the rate limit resets.
     */
    public function availableIn(string $key): int
    {
        $cacheKey = $this->getCacheKey($key);

        return RateLimiterFacade::availableIn($cacheKey);
    }

    /**
     * Clear the rate limit for the given key.
     */
    public function clear(string $key): void
    {
        $cacheKey = $this->getCacheKey($key);

        RateLimiterFacade::clear($cacheKey);
    }

    /**
     * Get the number of attempts made for the given key.
     */
    public function attempts(string $key): int
    {
        $cacheKey = $this->getCacheKey($key);
        $attempts = RateLimiterFacade::attempts($cacheKey);

        return is_int($attempts) ? $attempts : 0;
    }

    /**
     * Get a unique key for the current context (CLI or web request).
     */
    public function getContextKey(): string
    {
        if (app()->runningInConsole()) {
            return 'cli:' . gethostname();
        }

        $ip = request()->ip() ?? 'unknown';

        return 'web:' . $ip;
    }

    /**
     * Get the cache key for rate limiting.
     */
    protected function getCacheKey(string $key): string
    {
        return self::KEY_PREFIX . $key;
    }

    /**
     * Get the maximum number of attempts allowed.
     */
    public function getMaxAttempts(): int
    {
        return $this->maxAttempts;
    }

    /**
     * Get the decay time in minutes.
     */
    public function getDecayMinutes(): int
    {
        return $this->decayMinutes;
    }
}
