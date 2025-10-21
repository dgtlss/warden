<?php

namespace Dgtlss\Warden\Contracts;

interface PluginManagerInterface
{
    /**
     * Register a plugin.
     *
     * @param AuditPluginInterface $plugin
     * @return void
     */
    public function register(AuditPluginInterface $plugin): void;

    /**
     * Unregister a plugin.
     *
     * @param string $identifier
     * @return void
     */
    public function unregister(string $identifier): void;

    /**
     * Get a registered plugin by identifier.
     *
     * @param string $identifier
     * @return AuditPluginInterface|null
     */
    public function getPlugin(string $identifier): ?AuditPluginInterface;

    /**
     * Get all registered plugins.
     *
     * @return array<string, AuditPluginInterface>
     */
    public function getPlugins(): array;

    /**
     * Get all enabled plugins.
     *
     * @return array<string, AuditPluginInterface>
     */
    public function getEnabledPlugins(): array;

    /**
     * Check if a plugin is registered.
     *
     * @param string $identifier
     * @return bool
     */
    public function hasPlugin(string $identifier): bool;

    /**
     * Enable a plugin.
     *
     * @param string $identifier
     * @return void
     */
    public function enablePlugin(string $identifier): void;

    /**
     * Disable a plugin.
     *
     * @param string $identifier
     * @return void
     */
    public function disablePlugin(string $identifier): void;

    /**
     * Check if a plugin is enabled.
     *
     * @param string $identifier
     * @return bool
     */
    public function isPluginEnabled(string $identifier): bool;

    /**
     * Discover plugins from configured paths.
     *
     * @return void
     */
    public function discoverPlugins(): void;

    /**
     * Resolve plugin dependencies.
     *
     * @param string $identifier
     * @return array<string, bool> Array of dependency identifiers and their satisfaction status
     * @throws \RuntimeException If circular dependencies are detected
     */
    public function resolveDependencies(string $identifier): array;

    /**
     * Get plugins in dependency order.
     *
     * @return array<string, AuditPluginInterface>
     */
    public function getPluginsInDependencyOrder(): array;

    /**
     * Validate plugin compatibility.
     *
     * @param AuditPluginInterface $plugin
     * @return bool
     */
    public function validatePlugin(AuditPluginInterface $plugin): bool;

    /**
     * Get all audit classes from enabled plugins.
     *
     * @return array<string, string> Array of audit identifiers and class names
     */
    public function getAuditClasses(): array;

    /**
     * Get plugin configuration.
     *
     * @param string $identifier
     * @return array
     */
    public function getPluginConfig(string $identifier): array;

    /**
     * Set plugin configuration.
     *
     * @param string $identifier
     * @param array $config
     * @return void
     */
    public function setPluginConfig(string $identifier, array $config): void;
}