<?php

namespace Dgtlss\Warden\Contracts;

use Dgtlss\Warden\Services\PluginManager;

/**
 * Contract for Warden plugins.
 *
 * Plugins can extend Warden's functionality by providing:
 * - Custom audit services
 * - Custom notification channels
 * - Additional Artisan commands
 *
 * @example
 * ```php
 * class MyPlugin extends AbstractPlugin
 * {
 *     public function name(): string
 *     {
 *         return 'my-plugin';
 *     }
 *
 *     public function audits(): array
 *     {
 *         return [MyCustomAudit::class];
 *     }
 * }
 * ```
 */
interface WardenPlugin
{
    /**
     * Get the unique name of this plugin.
     *
     * Should be kebab-case and unique across all plugins.
     * Example: 'warden-docker', 'warden-aws', 'my-company-audits'
     */
    public function name(): string;

    /**
     * Get the version of this plugin.
     *
     * Should follow semantic versioning (e.g., '1.0.0').
     */
    public function version(): string;

    /**
     * Register the plugin with the PluginManager.
     *
     * Called during the registration phase before boot.
     * Use this to bind services or set up dependencies.
     */
    public function register(PluginManager $manager): void;

    /**
     * Boot the plugin after all plugins have been registered.
     *
     * Use this for any initialization that requires other plugins
     * or services to be available.
     */
    public function boot(): void;

    /**
     * Get the audit service classes provided by this plugin.
     *
     * Each class must implement Dgtlss\Warden\Contracts\AuditService.
     *
     * @return array<int, class-string<AuditService>>
     */
    public function audits(): array;

    /**
     * Get the notification channel classes provided by this plugin.
     *
     * Each class must implement Dgtlss\Warden\Contracts\NotificationChannel.
     *
     * @return array<int, class-string<NotificationChannel>>
     */
    public function channels(): array;

    /**
     * Get the Artisan command classes provided by this plugin.
     *
     * Each class must extend Illuminate\Console\Command.
     *
     * @return array<int, class-string<\Illuminate\Console\Command>>
     */
    public function commands(): array;

    /**
     * Get plugin metadata for display purposes.
     *
     * @return array{name: string, version: string, description: string, author: string|null}
     */
    public function metadata(): array;
}
