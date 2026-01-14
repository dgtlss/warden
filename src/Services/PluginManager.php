<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\AuditService;
use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\Contracts\WardenPlugin;
use Dgtlss\Warden\Exceptions\ConfigurationException;
use Illuminate\Console\Command;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\File;

/**
 * Manages Warden plugins lifecycle and discovery.
 *
 * The PluginManager handles:
 * - Manual plugin registration via config
 * - Auto-discovery of plugins from installed packages
 * - Collecting audits, channels, and commands from all plugins
 */
class PluginManager
{
    /**
     * Registered plugin instances.
     *
     * @var array<string, WardenPlugin>
     */
    protected array $plugins = [];

    /**
     * Whether plugins have been booted.
     */
    protected bool $booted = false;

    public function __construct(
        protected Application $app
    ) {
    }

    /**
     * Register a plugin instance.
     *
     * @throws ConfigurationException If a plugin with the same name is already registered
     */
    public function register(WardenPlugin $plugin): void
    {
        $name = $plugin->name();

        if ($this->isRegistered($name)) {
            throw ConfigurationException::pluginError(
                "Plugin '{$name}' is already registered"
            );
        }

        $this->plugins[$name] = $plugin;
        $plugin->register($this);
    }

    /**
     * Register a plugin by class name.
     *
     * @param string $pluginClass The fully qualified class name
     * @throws ConfigurationException If the class doesn't implement WardenPlugin
     */
    public function registerClass(string $pluginClass): void
    {
        if (!class_exists($pluginClass)) {
            throw ConfigurationException::pluginError(
                "Plugin class '{$pluginClass}' does not exist"
            );
        }

        $plugin = $this->app->make($pluginClass);

        if (!$plugin instanceof WardenPlugin) {
            throw ConfigurationException::pluginError(
                "Class '{$pluginClass}' does not implement WardenPlugin interface"
            );
        }

        $this->register($plugin);
    }

    /**
     * Discover and register plugins from installed Composer packages.
     *
     * Looks for packages with "extra.warden.plugin" in their composer.json.
     */
    public function discover(): void
    {
        if (!$this->isAutoDiscoveryEnabled()) {
            return;
        }

        $installedPath = base_path('vendor/composer/installed.json');

        if (!File::exists($installedPath)) {
            return;
        }

        $contents = File::get($installedPath);
        $installed = json_decode($contents, true);

        if (!is_array($installed)) {
            return;
        }

        $packages = $installed['packages'] ?? $installed;

        if (!is_array($packages)) {
            return;
        }

        foreach ($packages as $package) {
            if (!is_array($package)) {
                continue;
            }
            $this->discoverFromPackage($package);
        }
    }

    /**
     * Boot all registered plugins.
     *
     * Should be called after all plugins are registered.
     */
    public function boot(): void
    {
        if ($this->booted) {
            return;
        }

        foreach ($this->plugins as $plugin) {
            $plugin->boot();
        }

        $this->booted = true;
    }

    /**
     * Check if a plugin is registered by name.
     */
    public function isRegistered(string $name): bool
    {
        return isset($this->plugins[$name]);
    }

    /**
     * Get a registered plugin by name.
     */
    public function get(string $name): ?WardenPlugin
    {
        return $this->plugins[$name] ?? null;
    }

    /**
     * Get all registered plugins.
     *
     * @return array<string, WardenPlugin>
     */
    public function all(): array
    {
        return $this->plugins;
    }

    /**
     * Get all audit service classes from all plugins.
     *
     * @return array<int, class-string<AuditService>>
     */
    public function getAudits(): array
    {
        $audits = [];

        foreach ($this->plugins as $plugin) {
            $pluginAudits = $plugin->audits();

            foreach ($pluginAudits as $audit) {
                if (!in_array($audit, $audits, true)) {
                    $audits[] = $audit;
                }
            }
        }

        return $audits;
    }

    /**
     * Get all notification channel classes from all plugins.
     *
     * @return array<int, class-string<NotificationChannel>>
     */
    public function getChannels(): array
    {
        $channels = [];

        foreach ($this->plugins as $plugin) {
            $pluginChannels = $plugin->channels();

            foreach ($pluginChannels as $channel) {
                if (!in_array($channel, $channels, true)) {
                    $channels[] = $channel;
                }
            }
        }

        return $channels;
    }

    /**
     * Get all command classes from all plugins.
     *
     * @return array<int, class-string<Command>>
     */
    public function getCommands(): array
    {
        $commands = [];

        foreach ($this->plugins as $plugin) {
            $pluginCommands = $plugin->commands();

            foreach ($pluginCommands as $command) {
                if (!in_array($command, $commands, true)) {
                    $commands[] = $command;
                }
            }
        }

        return $commands;
    }

    /**
     * Get metadata for all registered plugins.
     *
     * @return array<string, array{name: string, version: string, description: string, author: string|null}>
     */
    public function getMetadata(): array
    {
        $metadata = [];

        foreach ($this->plugins as $name => $plugin) {
            $metadata[$name] = $plugin->metadata();
        }

        return $metadata;
    }

    /**
     * Get the count of registered plugins.
     */
    public function count(): int
    {
        return count($this->plugins);
    }

    /**
     * Check if auto-discovery is enabled.
     */
    protected function isAutoDiscoveryEnabled(): bool
    {
        $enabled = config('warden.plugins.auto_discover', true);

        return is_bool($enabled) ? $enabled : true;
    }

    /**
     * Attempt to discover a plugin from a package definition.
     *
     * @param array<mixed, mixed> $package
     */
    protected function discoverFromPackage(array $package): void
    {
        $extra = $package['extra'] ?? null;

        if (!is_array($extra)) {
            return;
        }

        $wardenConfig = $extra['warden'] ?? null;

        if (!is_array($wardenConfig)) {
            return;
        }

        $pluginClass = $wardenConfig['plugin'] ?? null;

        if (!is_string($pluginClass) || $pluginClass === '') {
            return;
        }

        if (!class_exists($pluginClass)) {
            return;
        }

        try {
            $this->registerClass($pluginClass);
        } catch (ConfigurationException $e) {
            // Skip plugins that fail to register (e.g., duplicates)
        }
    }

    /**
     * Register plugins from config.
     */
    public function registerFromConfig(): void
    {
        $registered = config('warden.plugins.registered', []);

        if (!is_array($registered)) {
            return;
        }

        foreach ($registered as $pluginClass) {
            if (!is_string($pluginClass)) {
                continue;
            }

            try {
                $this->registerClass($pluginClass);
            } catch (ConfigurationException $e) {
                // Log or handle failed plugin registration
            }
        }
    }
}
