<?php

namespace Dgtlss\Warden\Abstracts;

use Dgtlss\Warden\Contracts\AuditDependencyInterface;

abstract class AbstractAuditDependency implements AuditDependencyInterface
{
    protected string $identifier;
    protected string $type;
    protected int $priority = 100;
    protected array $config = [];

    public function __construct(string $identifier, string $type, int $priority = 100)
    {
        $this->identifier = $identifier;
        $this->type = $type;
        $this->priority = $priority;
    }

    /**
     * Get the dependency identifier.
     *
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * Get the dependency type.
     *
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Get the priority of this dependency.
     *
     * @return int
     */
    public function getPriority(): int
    {
        return $this->priority;
    }

    /**
     * Get configuration options for this dependency.
     *
     * @return array
     */
    public function getConfigOptions(): array
    {
        return [];
    }

    /**
     * Set configuration for this dependency.
     *
     * @param array $config
     * @return void
     */
    public function setConfig(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }

    /**
     * Get configuration value.
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    protected function getConfig(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * Get the reason why the dependency is not satisfied.
     *
     * @return string|null
     */
    public function getUnsatisfiedReason(): ?string
    {
        return null;
    }

    /**
     * Attempt to resolve the dependency.
     *
     * @return bool
     */
    public function resolve(): bool
    {
        return false;
    }
}