<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditDependencyInterface;
use Illuminate\Support\Facades\Log;

abstract class AbstractAuditService
{
    protected $findings = [];
    protected array $dependencies = [];
    protected array $config = [];
    protected bool $initialized = false;
    
    abstract public function run(): bool;
    abstract public function getName(): string;
    
    public function getFindings(): array
    {
        return $this->findings;
    }

    /**
     * Get the dependencies required by this audit.
     *
     * @return array<AuditDependencyInterface>
     */
    public function getDependencies(): array
    {
        return $this->dependencies;
    }

    /**
     * Add a dependency to this audit.
     *
     * @param AuditDependencyInterface $dependency
     * @return void
     */
    public function addDependency(AuditDependencyInterface $dependency): void
    {
        $this->dependencies[$dependency->getIdentifier()] = $dependency;
    }

    /**
     * Check if all dependencies are satisfied.
     *
     * @return bool
     */
    public function areDependenciesSatisfied(): bool
    {
        foreach ($this->dependencies as $dependency) {
            if (!$dependency->isSatisfied()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get unsatisfied dependencies.
     *
     * @return array<AuditDependencyInterface>
     */
    public function getUnsatisfiedDependencies(): array
    {
        $unsatisfied = [];
        foreach ($this->dependencies as $dependency) {
            if (!$dependency->isSatisfied()) {
                $unsatisfied[] = $dependency;
            }
        }
        return $unsatisfied;
    }

    /**
     * Initialize the audit with configuration.
     *
     * @param array $config
     * @return void
     */
    public function initialize(array $config = []): void
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);
        $this->initialized = true;
        $this->onInitialize();
    }

    /**
     * Get the audit configuration.
     *
     * @return array
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Get a specific configuration value.
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    protected function getConfigValue(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * Check if the audit is enabled.
     *
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->getConfigValue('enabled', true);
    }

    /**
     * Get the timeout for this audit.
     *
     * @return int
     */
    public function getTimeout(): int
    {
        return $this->getConfigValue('timeout', 300);
    }

    /**
     * Get the retry attempts for this audit.
     *
     * @return int
     */
    public function getRetryAttempts(): int
    {
        return $this->getConfigValue('retry_attempts', 3);
    }

    /**
     * Check if this audit should run.
     *
     * @return bool
     */
    public function shouldRun(): bool
    {
        if (!$this->initialized) {
            return false;
        }

        if (!$this->isEnabled()) {
            return false;
        }

        if (!$this->areDependenciesSatisfied()) {
            $unsatisfied = $this->getUnsatisfiedDependencies();
            foreach ($unsatisfied as $dependency) {
                Log::warning("Audit {$this->getName()} dependency not satisfied: " . $dependency->getUnsatisfiedReason());
            }
            return false;
        }

        return $this->onShouldRun();
    }

    /**
     * Get the default configuration for this audit.
     *
     * @return array
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled' => true,
            'timeout' => 300,
            'retry_attempts' => 3,
        ];
    }

    /**
     * Called when the audit is initialized.
     *
     * @return void
     */
    protected function onInitialize(): void
    {
        // Override in subclasses
    }

    /**
     * Called to determine if the audit should run.
     *
     * @return bool
     */
    protected function onShouldRun(): bool
    {
        return true;
    }

    /**
     * Log a debug message.
     *
     * @param string $message
     * @param array $context
     * @return void
     */
    protected function debug(string $message, array $context = []): void
    {
        Log::debug("[{$this->getName()}] {$message}", $context);
    }

    /**
     * Log an info message.
     *
     * @param string $message
     * @param array $context
     * @return void
     */
    protected function info(string $message, array $context = []): void
    {
        Log::info("[{$this->getName()}] {$message}", $context);
    }

    /**
     * Log a warning message.
     *
     * @param string $message
     * @param array $context
     * @return void
     */
    protected function warning(string $message, array $context = []): void
    {
        Log::warning("[{$this->getName()}] {$message}", $context);
    }

    /**
     * Log an error message.
     *
     * @param string $message
     * @param array $context
     * @return void
     */
    protected function error(string $message, array $context = []): void
    {
        Log::error("[{$this->getName()}] {$message}", $context);
    }

    protected function addFinding(array $finding): void
    {
        $this->findings[] = array_merge($finding, [
            'source' => $this->getName()
        ]);
    }
}