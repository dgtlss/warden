<?php

namespace Dgtlss\Warden\Contracts;

interface AuditDependencyInterface
{
    /**
     * Get the dependency identifier.
     *
     * @return string
     */
    public function getIdentifier(): string;

    /**
     * Get the dependency type (service, package, system, etc.).
     *
     * @return string
     */
    public function getType(): string;

    /**
     * Check if the dependency is satisfied.
     *
     * @return bool
     */
    public function isSatisfied(): bool;

    /**
     * Get the reason why the dependency is not satisfied.
     *
     * @return string|null
     */
    public function getUnsatisfiedReason(): ?string;

    /**
     * Get the priority of this dependency (higher = more important).
     *
     * @return int
     */
    public function getPriority(): int;

    /**
     * Attempt to resolve the dependency.
     *
     * @return bool True if successfully resolved
     */
    public function resolve(): bool;

    /**
     * Get configuration options for this dependency.
     *
     * @return array
     */
    public function getConfigOptions(): array;
}