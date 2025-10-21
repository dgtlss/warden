<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\AuditPluginInterface;
use Dgtlss\Warden\Contracts\PluginManagerInterface;
use Dgtlss\Warden\Contracts\AuditDependencyInterface;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use RuntimeException;

class PluginManager implements PluginManagerInterface
{
    protected array $plugins = [];
    protected array $enabledPlugins = [];
    protected array $pluginConfigs = [];
    protected array $dependencyGraph = [];
    protected string $wardenVersion;

    public function __construct()
    {
        $this->wardenVersion = $this->getWardenVersion();
    }

    /**
     * Register a plugin.
     *
     * @param AuditPluginInterface $plugin
     * @return void
     */
    public function register(AuditPluginInterface $plugin): void
    {
        $identifier = $plugin->getIdentifier();

        if ($this->hasPlugin($identifier)) {
            Log::warning("Plugin {$identifier} is already registered");
            return;
        }

        if (!$this->validatePlugin($plugin)) {
            throw new RuntimeException("Plugin {$identifier} failed validation");
        }

        $this->plugins[$identifier] = $plugin;
        $this->dependencyGraph[$identifier] = $plugin->getDependencies();

        // Load plugin configuration
        $config = $this->getPluginConfig($identifier);
        $plugin->initialize($config);

        // Enable by default if not explicitly disabled
        if ($config['enabled'] ?? true) {
            $this->enablePlugin($identifier);
        }

        Log::info("Plugin {$identifier} registered successfully");
    }

    /**
     * Unregister a plugin.
     *
     * @param string $identifier
     * @return void
     */
    public function unregister(string $identifier): void
    {
        if (!$this->hasPlugin($identifier)) {
            return;
        }

        $plugin = $this->plugins[$identifier];
        
        // Cleanup plugin
        $plugin->cleanup();
        
        // Remove from enabled plugins
        unset($this->enabledPlugins[$identifier]);
        
        // Remove from registry
        unset($this->plugins[$identifier]);
        unset($this->dependencyGraph[$identifier]);

        Log::info("Plugin {$identifier} unregistered");
    }

    /**
     * Get a registered plugin by identifier.
     *
     * @param string $identifier
     * @return AuditPluginInterface|null
     */
    public function getPlugin(string $identifier): ?AuditPluginInterface
    {
        return $this->plugins[$identifier] ?? null;
    }

    /**
     * Get all registered plugins.
     *
     * @return array<string, AuditPluginInterface>
     */
    public function getPlugins(): array
    {
        return $this->plugins;
    }

    /**
     * Get all enabled plugins.
     *
     * @return array<string, AuditPluginInterface>
     */
    public function getEnabledPlugins(): array
    {
        return array_intersect_key($this->plugins, $this->enabledPlugins);
    }

    /**
     * Check if a plugin is registered.
     *
     * @param string $identifier
     * @return bool
     */
    public function hasPlugin(string $identifier): bool
    {
        return isset($this->plugins[$identifier]);
    }

    /**
     * Enable a plugin.
     *
     * @param string $identifier
     * @return void
     */
    public function enablePlugin(string $identifier): void
    {
        if (!$this->hasPlugin($identifier)) {
            throw new RuntimeException("Plugin {$identifier} is not registered");
        }

        // Check dependencies
        $dependencies = $this->resolveDependencies($identifier);
        $unsatisfied = array_filter($dependencies, fn($satisfied) => !$satisfied);
        
        if (!empty($unsatisfied)) {
            $unsatisfiedDeps = implode(', ', array_keys($unsatisfied));
            throw new RuntimeException("Cannot enable plugin {$identifier}: unsatisfied dependencies: {$unsatisfiedDeps}");
        }

        $this->enabledPlugins[$identifier] = true;
        Log::info("Plugin {$identifier} enabled");
    }

    /**
     * Disable a plugin.
     *
     * @param string $identifier
     * @return void
     */
    public function disablePlugin(string $identifier): void
    {
        if (!$this->hasPlugin($identifier)) {
            return;
        }

        // Check if other enabled plugins depend on this one
        $dependents = $this->findDependents($identifier);
        $enabledDependents = array_intersect($dependents, array_keys($this->enabledPlugins));
        
        if (!empty($enabledDependents)) {
            $dependentList = implode(', ', $enabledDependents);
            Log::warning("Cannot disable plugin {$identifier}: required by enabled plugins: {$dependentList}");
            return;
        }

        unset($this->enabledPlugins[$identifier]);
        Log::info("Plugin {$identifier} disabled");
    }

    /**
     * Check if a plugin is enabled.
     *
     * @param string $identifier
     * @return bool
     */
    public function isPluginEnabled(string $identifier): bool
    {
        return isset($this->enabledPlugins[$identifier]);
    }

    /**
     * Discover plugins from configured paths.
     *
     * @return void
     */
    public function discoverPlugins(): void
    {
        $paths = config('warden.plugins.discovery_paths', [
            base_path('app/Warden/Plugins'),
            base_path('plugins'),
            __DIR__ . '/../Plugins'
        ]);

        foreach ($paths as $path) {
            if (!is_dir($path)) {
                continue;
            }

            $this->discoverPluginsInPath($path);
        }
    }

    /**
     * Resolve plugin dependencies.
     *
     * @param string $identifier
     * @return array<string, bool>
     * @throws RuntimeException If circular dependencies are detected
     */
    public function resolveDependencies(string $identifier): array
    {
        if (!$this->hasPlugin($identifier)) {
            throw new RuntimeException("Plugin {$identifier} is not registered");
        }

        $resolved = [];
        $visiting = [];

        $this->resolveDependenciesRecursive($identifier, $resolved, $visiting);

        return $resolved;
    }

    /**
     * Get plugins in dependency order.
     *
     * @return array<string, AuditPluginInterface>
     */
    public function getPluginsInDependencyOrder(): array
    {
        $ordered = [];
        $visited = [];
        $visiting = [];

        foreach ($this->getEnabledPlugins() as $identifier => $plugin) {
            if (!isset($visited[$identifier])) {
                $this->visitPlugin($identifier, $ordered, $visited, $visiting);
            }
        }

        return array_map(fn($id) => $this->plugins[$id], $ordered);
    }

    /**
     * Validate plugin compatibility.
     *
     * @param AuditPluginInterface $plugin
     * @return bool
     */
    public function validatePlugin(AuditPluginInterface $plugin): bool
    {
        $identifier = $plugin->getIdentifier();

        // Check minimum version requirement
        if (version_compare($this->wardenVersion, $plugin->getMinimumWardenVersion(), '<')) {
            Log::error("Plugin {$identifier} requires Warden {$plugin->getMinimumWardenVersion()} or higher, current version is {$this->wardenVersion}");
            return false;
        }

        // Check maximum version constraint
        $maxVersion = $plugin->getMaximumWardenVersion();
        if ($maxVersion && version_compare($this->wardenVersion, $maxVersion, '>')) {
            Log::error("Plugin {$identifier} requires Warden {$maxVersion} or lower, current version is {$this->wardenVersion}");
            return false;
        }

        // Check compatibility
        if (!$plugin->isCompatible()) {
            Log::error("Plugin {$identifier} is not compatible with current environment");
            return false;
        }

        // Validate audit classes
        foreach ($plugin->getAuditClasses() as $class) {
            if (!class_exists($class)) {
                Log::error("Plugin {$identifier} references non-existent audit class: {$class}");
                return false;
            }
        }

        return true;
    }

    /**
     * Get all audit classes from enabled plugins.
     *
     * @return array<string, string>
     */
    public function getAuditClasses(): array
    {
        $auditClasses = [];

        foreach ($this->getEnabledPlugins() as $plugin) {
            foreach ($plugin->getAuditClasses() as $class) {
                $auditClasses[$class] = $class;
            }
        }

        return $auditClasses;
    }

    /**
     * Get plugin configuration.
     *
     * @param string $identifier
     * @return array
     */
    public function getPluginConfig(string $identifier): array
    {
        $defaultConfig = [
            'enabled' => true,
            'priority' => 100,
            'timeout' => 300,
            'retry_attempts' => 3,
        ];

        $config = config("warden.plugins.config.{$identifier}", []);
        
        return array_merge($defaultConfig, $config);
    }

    /**
     * Set plugin configuration.
     *
     * @param string $identifier
     * @param array $config
     * @return void
     */
    public function setPluginConfig(string $identifier, array $config): void
    {
        $this->pluginConfigs[$identifier] = $config;
    }

    /**
     * Discover plugins in a specific path.
     *
     * @param string $path
     * @return void
     */
    protected function discoverPluginsInPath(string $path): void
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $this->loadPluginFromFile($file->getPathname());
            }
        }
    }

    /**
     * Load a plugin from a file.
     *
     * @param string $filePath
     * @return void
     */
    protected function loadPluginFromFile(string $filePath): void
    {
        try {
            require_once $filePath;

            // Extract class name from file
            $content = file_get_contents($filePath);
            if (!preg_match('/namespace\s+([^;]+);/', $content, $namespaceMatch)) {
                return;
            }

            if (!preg_match('/class\s+(\w+)/', $content, $classMatch)) {
                return;
            }

            $className = $namespaceMatch[1] . '\\' . $classMatch[1];
            
            if (!class_exists($className)) {
                return;
            }

            $reflection = new ReflectionClass($className);
            
            if ($reflection->isAbstract() || !$reflection->implementsInterface(AuditPluginInterface::class)) {
                return;
            }

            $plugin = new $className();
            $this->register($plugin);

        } catch (\Exception $e) {
            Log::error("Failed to load plugin from {$filePath}: " . $e->getMessage());
        }
    }

    /**
     * Recursively resolve dependencies.
     *
     * @param string $identifier
     * @param array $resolved
     * @param array $visiting
     * @return void
     * @throws RuntimeException
     */
    protected function resolveDependenciesRecursive(string $identifier, array &$resolved, array &$visiting): void
    {
        if (isset($visiting[$identifier])) {
            throw new RuntimeException("Circular dependency detected involving plugin: {$identifier}");
        }

        if (isset($resolved[$identifier])) {
            return;
        }

        $visiting[$identifier] = true;

        $dependencies = $this->dependencyGraph[$identifier] ?? [];
        
        foreach ($dependencies as $dependency) {
            if (!$this->hasPlugin($dependency)) {
                $resolved[$dependency] = false;
                continue;
            }

            $this->resolveDependenciesRecursive($dependency, $resolved, $visiting);
            
            if (!$resolved[$dependency]) {
                $resolved[$dependency] = false;
            }
        }

        unset($visiting[$identifier]);
        
        // All dependencies must be satisfied
        $resolved[$identifier] = empty(array_filter($dependencies, fn($dep) => ($resolved[$dep] ?? false) === false));
    }

    /**
     * Visit plugin for topological sorting.
     *
     * @param string $identifier
     * @param array $ordered
     * @param array $visited
     * @param array $visiting
     * @return void
     * @throws RuntimeException
     */
    protected function visitPlugin(string $identifier, array &$ordered, array &$visited, array &$visiting): void
    {
        if (isset($visiting[$identifier])) {
            throw new RuntimeException("Circular dependency detected involving plugin: {$identifier}");
        }

        if (isset($visited[$identifier])) {
            return;
        }

        $visiting[$identifier] = true;

        $dependencies = $this->dependencyGraph[$identifier] ?? [];
        
        foreach ($dependencies as $dependency) {
            if ($this->isPluginEnabled($dependency)) {
                $this->visitPlugin($dependency, $ordered, $visited, $visiting);
            }
        }

        unset($visiting[$identifier]);
        $visited[$identifier] = true;
        $ordered[] = $identifier;
    }

    /**
     * Find plugins that depend on the given plugin.
     *
     * @param string $identifier
     * @return array
     */
    protected function findDependents(string $identifier): array
    {
        $dependents = [];
        
        foreach ($this->dependencyGraph as $plugin => $dependencies) {
            if (in_array($identifier, $dependencies)) {
                $dependents[] = $plugin;
            }
        }
        
        return $dependents;
    }

    /**
     * Get the current Warden version.
     *
     * @return string
     */
    protected function getWardenVersion(): string
    {
        $composerJson = __DIR__ . '/../../composer.json';
        
        if (file_exists($composerJson)) {
            $content = json_decode(file_get_contents($composerJson), true);
            return $content['version'] ?? '2.0.0';
        }
        
        return '2.0.0';
    }
}