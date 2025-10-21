<?php

namespace Dgtlss\Warden\Abstracts;

use Dgtlss\Warden\Contracts\AuditPluginInterface;
use Dgtlss\Warden\Contracts\AuditDependencyInterface;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

abstract class AbstractAuditPlugin implements AuditPluginInterface
{
    protected array $config = [];
    protected bool $initialized = false;

    /**
     * Get the default configuration for this plugin.
     *
     * @return array
     */
    protected function getDefaultConfig(): array
    {
        return [
            'enabled' => true,
            'priority' => 100,
            'timeout' => 300,
            'retry_attempts' => 3,
        ];
    }

    /**
     * Get the plugin identifier from class name.
     *
     * @return string
     */
    protected function generateIdentifier(): string
    {
        $className = class_basename($this);
        return Str::kebab(str_replace('Plugin', '', $className));
    }

    /**
     * Check if a PHP extension is available.
     *
     * @param string $extension
     * @return bool
     */
    protected function checkExtension(string $extension): bool
    {
        return extension_loaded($extension);
    }

    /**
     * Check if a command is available in the system PATH.
     *
     * @param string $command
     * @return bool
     */
    protected function checkCommand(string $command): bool
    {
        $windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $testCommand = $windows ? 'where' : 'which';
        
        $process = new \Symfony\Component\Process\Process([$testCommand, $command]);
        $process->run();
        
        return $process->isSuccessful();
    }

    /**
     * Check if a file or directory exists.
     *
     * @param string $path
     * @return bool
     */
    protected function checkFileExists(string $path): bool
    {
        return file_exists(base_path($path));
    }

    /**
     * Get a configuration value.
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
     * Set a configuration value.
     *
     * @param string $key
     * @param mixed $value
     * @return void
     */
    protected function setConfig(string $key, $value): void
    {
        $this->config[$key] = $value;
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
        Log::debug("[{$this->getIdentifier()}] {$message}", $context);
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
        Log::info("[{$this->getIdentifier()}] {$message}", $context);
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
        Log::warning("[{$this->getIdentifier()}] {$message}", $context);
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
        Log::error("[{$this->getIdentifier()}] {$message}", $context);
    }

    /**
     * Check if the plugin has been initialized.
     *
     * @return bool
     */
    public function isInitialized(): bool
    {
        return $this->initialized;
    }

    /**
     * Get the plugin identifier.
     *
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->generateIdentifier();
    }

    /**
     * Get the minimum Warden version required.
     *
     * @return string
     */
    public function getMinimumWardenVersion(): string
    {
        return '2.0.0';
    }

    /**
     * Get the maximum Warden version supported.
     *
     * @return string|null
     */
    public function getMaximumWardenVersion(): ?string
    {
        return null;
    }

    /**
     * Get the dependencies required by this plugin.
     *
     * @return array
     */
    public function getDependencies(): array
    {
        return [];
    }

    /**
     * Get the configuration schema for this plugin.
     *
     * @return array
     */
    public function getConfigSchema(): array
    {
        return [
            'enabled' => [
                'type' => 'boolean',
                'default' => true,
                'description' => 'Whether this plugin is enabled'
            ],
            'priority' => [
                'type' => 'integer',
                'default' => 100,
                'min' => 1,
                'max' => 1000,
                'description' => 'Plugin execution priority (lower = earlier)'
            ],
            'timeout' => [
                'type' => 'integer',
                'default' => 300,
                'min' => 1,
                'max' => 3600,
                'description' => 'Timeout in seconds for plugin operations'
            ],
            'retry_attempts' => [
                'type' => 'integer',
                'default' => 3,
                'min' => 0,
                'max' => 10,
                'description' => 'Number of retry attempts for failed operations'
            ]
        ];
    }

    /**
     * Initialize the plugin.
     *
     * @param array $config
     * @return void
     */
    public function initialize(array $config = []): void
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);
        $this->initialized = true;
        
        $this->info('Plugin initialized', ['config' => $this->config]);
    }

    /**
     * Cleanup when the plugin is disabled/uninstalled.
     *
     * @return void
     */
    public function cleanup(): void
    {
        $this->info('Plugin cleanup completed');
        $this->initialized = false;
    }
}