<?php

namespace Dgtlss\Warden\Contracts;

interface AuditPluginInterface
{
    /**
     * Get the unique identifier for this plugin.
     *
     * @return string
     */
    public function getIdentifier(): string;

    /**
     * Get the human-readable name of this plugin.
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Get the description of what this plugin does.
     *
     * @return string
     */
    public function getDescription(): string;

    /**
     * Get the version of this plugin.
     *
     * @return string
     */
    public function getVersion(): string;

    /**
     * Get the author of this plugin.
     *
     * @return string
     */
    public function getAuthor(): string;

    /**
     * Get the dependencies required by this plugin.
     *
     * @return array Array of plugin identifiers that this plugin depends on
     */
    public function getDependencies(): array;

    /**
     * Get the audit classes provided by this plugin.
     *
     * @return array Array of audit class names
     */
    public function getAuditClasses(): array;

    /**
     * Check if this plugin is compatible with the current environment.
     *
     * @return bool
     */
    public function isCompatible(): bool;

    /**
     * Get the configuration schema for this plugin.
     *
     * @return array
     */
    public function getConfigSchema(): array;

    /**
     * Initialize the plugin.
     *
     * @param array $config Plugin configuration
     * @return void
     */
    public function initialize(array $config = []): void;

    /**
     * Cleanup when the plugin is disabled/uninstalled.
     *
     * @return void
     */
    public function cleanup(): void;

    /**
     * Get the minimum Warden version required.
     *
     * @return string
     */
    public function getMinimumWardenVersion(): string;

    /**
     * Get the maximum Warden version supported (optional).
     *
     * @return string|null
     */
    public function getMaximumWardenVersion(): ?string;
}