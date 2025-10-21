<?php

namespace Dgtlss\Warden\Services\Dependencies;

use Dgtlss\Warden\Contracts\AuditDependencyInterface;
use Dgtlss\Warden\Contracts\PluginManagerInterface;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

class DependencyResolver
{
    protected PluginManagerInterface $pluginManager;
    protected array $dependencies = [];
    protected array $resolutionCache = [];

    public function __construct(PluginManagerInterface $pluginManager)
    {
        $this->pluginManager = $pluginManager;
    }

    /**
     * Add a dependency to resolve.
     *
     * @param AuditDependencyInterface $dependency
     * @return void
     */
    public function addDependency(AuditDependencyInterface $dependency): void
    {
        $this->dependencies[$dependency->getIdentifier()] = $dependency;
        $this->clearCache();
    }

    /**
     * Remove a dependency.
     *
     * @param string $identifier
     * @return void
     */
    public function removeDependency(string $identifier): void
    {
        unset($this->dependencies[$identifier]);
        $this->clearCache();
    }

    /**
     * Get all dependencies.
     *
     * @return array<string, AuditDependencyInterface>
     */
    public function getDependencies(): array
    {
        return $this->dependencies;
    }

    /**
     * Get dependencies by type.
     *
     * @param string $type
     * @return array<string, AuditDependencyInterface>
     */
    public function getDependenciesByType(string $type): array
    {
        return array_filter($this->dependencies, fn($dep) => $dep->getType() === $type);
    }

    /**
     * Check if a dependency is satisfied.
     *
     * @param string $identifier
     * @return bool
     */
    public function isSatisfied(string $identifier): bool
    {
        if (!isset($this->dependencies[$identifier])) {
            return false;
        }

        if (isset($this->resolutionCache[$identifier])) {
            return $this->resolutionCache[$identifier];
        }

        $satisfied = $this->dependencies[$identifier]->isSatisfied();
        $this->resolutionCache[$identifier] = $satisfied;

        return $satisfied;
    }

    /**
     * Get unsatisfied dependencies.
     *
     * @return array<string, AuditDependencyInterface>
     */
    public function getUnsatisfiedDependencies(): array
    {
        $unsatisfied = [];
        
        foreach ($this->dependencies as $identifier => $dependency) {
            if (!$this->isSatisfied($identifier)) {
                $unsatisfied[$identifier] = $dependency;
            }
        }
        
        return $unsatisfied;
    }

    /**
     * Get unsatisfied dependencies grouped by type.
     *
     * @return array<string, array<string, AuditDependencyInterface>>
     */
    public function getUnsatisfiedDependenciesByType(): array
    {
        $grouped = [];
        
        foreach ($this->getUnsatisfiedDependencies() as $identifier => $dependency) {
            $type = $dependency->getType();
            $grouped[$type][$identifier] = $dependency;
        }
        
        return $grouped;
    }

    /**
     * Attempt to resolve all dependencies.
     *
     * @return array<string, bool> Resolution results
     */
    public function resolveAll(): array
    {
        $results = [];
        
        // Sort dependencies by priority (higher priority first)
        $sortedDependencies = $this->sortByPriority();
        
        foreach ($sortedDependencies as $identifier => $dependency) {
            $results[$identifier] = $this->resolveDependency($identifier);
        }
        
        return $results;
    }

    /**
     * Attempt to resolve a specific dependency.
     *
     * @param string $identifier
     * @return bool
     */
    public function resolveDependency(string $identifier): bool
    {
        if (!isset($this->dependencies[$identifier])) {
            return false;
        }

        $dependency = $this->dependencies[$identifier];
        
        if ($this->isSatisfied($identifier)) {
            return true;
        }

        try {
            $result = $dependency->resolve();
            $this->clearCache(); // Clear cache after resolution attempt
            
            if ($result) {
                Log::info("Dependency {$identifier} resolved successfully");
            } else {
                Log::warning("Failed to resolve dependency {$identifier}: " . $dependency->getUnsatisfiedReason());
            }
            
            return $result;
        } catch (\Exception $e) {
            Log::error("Error resolving dependency {$identifier}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get a resolution report.
     *
     * @return array
     */
    public function getResolutionReport(): array
    {
        $report = [
            'total' => count($this->dependencies),
            'satisfied' => 0,
            'unsatisfied' => 0,
            'resolvable' => 0,
            'unresolvable' => 0,
            'details' => []
        ];

        foreach ($this->dependencies as $identifier => $dependency) {
            $isSatisfied = $this->isSatisfied($identifier);
            $canResolve = $dependency->resolve();
            
            if ($isSatisfied) {
                $report['satisfied']++;
            } else {
                $report['unsatisfied']++;
                
                if ($canResolve) {
                    $report['resolvable']++;
                } else {
                    $report['unresolvable']++;
                }
            }
            
            $report['details'][$identifier] = [
                'type' => $dependency->getType(),
                'priority' => $dependency->getPriority(),
                'satisfied' => $isSatisfied,
                'resolvable' => $canResolve,
                'reason' => $isSatisfied ? null : $dependency->getUnsatisfiedReason(),
                'config_options' => $dependency->getConfigOptions()
            ];
        }

        return $report;
    }

    /**
     * Create a PHP extension dependency.
     *
     * @param string $extension
     * @param int $priority
     * @return PhpExtensionDependency
     */
    public function createPhpExtensionDependency(string $extension, int $priority = 100): PhpExtensionDependency
    {
        return new PhpExtensionDependency($extension, $priority);
    }

    /**
     * Create a system command dependency.
     *
     * @param string $command
     * @param array $checkArgs
     * @param string|null $installCommand
     * @param int $priority
     * @return SystemCommandDependency
     */
    public function createSystemCommandDependency(
        string $command,
        array $checkArgs = [],
        ?string $installCommand = null,
        int $priority = 100
    ): SystemCommandDependency {
        return new SystemCommandDependency($command, $checkArgs, $installCommand, $priority);
    }

    /**
     * Create a file dependency.
     *
     * @param string $path
     * @param bool $mustExist
     * @param bool $isDirectory
     * @param int $priority
     * @return FileDependency
     */
    public function createFileDependency(
        string $path,
        bool $mustExist = true,
        bool $isDirectory = false,
        int $priority = 100
    ): FileDependency {
        return new FileDependency($path, $mustExist, $isDirectory, $priority);
    }

    /**
     * Create a plugin dependency.
     *
     * @param string $requiredPlugin
     * @param string $minimumVersion
     * @param int $priority
     * @return PluginDependency
     */
    public function createPluginDependency(
        string $requiredPlugin,
        string $minimumVersion = '1.0.0',
        int $priority = 100
    ): PluginDependency {
        return new PluginDependency($this->pluginManager, $requiredPlugin, $minimumVersion, $priority);
    }

    /**
     * Sort dependencies by priority.
     *
     * @return array<string, AuditDependencyInterface>
     */
    protected function sortByPriority(): array
    {
        $dependencies = $this->dependencies;
        
        uasort($dependencies, function ($a, $b) {
            return $b->getPriority() <=> $a->getPriority();
        });
        
        return $dependencies;
    }

    /**
     * Clear the resolution cache.
     *
     * @return void
     */
    protected function clearCache(): void
    {
        $this->resolutionCache = [];
    }
}