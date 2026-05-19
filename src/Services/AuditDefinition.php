<?php

namespace Dgtlss\Warden\Services;

use Closure;
use Dgtlss\Warden\Contracts\AuditServiceInterface;

class AuditDefinition
{
    /**
     * @param array<int, string> $profiles
     * @param array<int, string> $cachePaths
     * @param array<int, string> $cacheConfig
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        protected readonly Closure $factory,
        public readonly array $profiles = ['legacy', 'recommended', 'ci-strict', 'runtime-safe'],
        public readonly array $cachePaths = [],
        public readonly array $cacheConfig = [],
        public readonly bool $cacheable = true,
    ) {
    }

    public function make(): AuditServiceInterface
    {
        $audit = ($this->factory)();

        if (!$audit instanceof AuditServiceInterface) {
            throw new \RuntimeException(sprintf('Audit definition [%s] did not resolve to an audit service.', $this->id));
        }

        return $audit;
    }

    public function supportsProfile(string $profile): bool
    {
        return in_array($profile, $this->profiles, true);
    }
}
