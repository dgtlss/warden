<?php

namespace Dgtlss\Warden\Services\Dependencies;

use Dgtlss\Warden\Abstracts\AbstractAuditDependency;
use Dgtlss\Warden\Contracts\PluginManagerInterface;

class PluginDependency extends AbstractAuditDependency
{
    protected PluginManagerInterface $pluginManager;
    protected string $requiredPlugin;
    protected string $minimumVersion;

    public function __construct(
        PluginManagerInterface $pluginManager,
        string $requiredPlugin,
        string $minimumVersion = '1.0.0',
        int $priority = 100
    ) {
        parent::__construct("plugin-{$requiredPlugin}", 'plugin', $priority);
        $this->pluginManager = $pluginManager;
        $this->requiredPlugin = $requiredPlugin;
        $this->minimumVersion = $minimumVersion;
    }

    /**
     * Check if the dependency is satisfied.
     *
     * @return bool
     */
    public function isSatisfied(): bool
    {
        if (!$this->pluginManager->hasPlugin($this->requiredPlugin)) {
            return false;
        }

        if (!$this->pluginManager->isPluginEnabled($this->requiredPlugin)) {
            return false;
        }

        $plugin = $this->pluginManager->getPlugin($this->requiredPlugin);
        
        return version_compare($plugin->getVersion(), $this->minimumVersion, '>=');
    }

    /**
     * Get the reason why the dependency is not satisfied.
     *
     * @return string|null
     */
    public function getUnsatisfiedReason(): ?string
    {
        if ($this->isSatisfied()) {
            return null;
        }

        if (!$this->pluginManager->hasPlugin($this->requiredPlugin)) {
            return "Plugin '{$this->requiredPlugin}' is not registered";
        }

        if (!$this->pluginManager->isPluginEnabled($this->requiredPlugin)) {
            return "Plugin '{$this->requiredPlugin}' is not enabled";
        }

        $plugin = $this->pluginManager->getPlugin($this->requiredPlugin);
        $currentVersion = $plugin->getVersion();
        
        return "Plugin '{$this->requiredPlugin}' version {$currentVersion} is below required version {$this->minimumVersion}";
    }

    /**
     * Attempt to resolve the dependency.
     *
     * @return bool
     */
    public function resolve(): bool
    {
        try {
            if (!$this->pluginManager->hasPlugin($this->requiredPlugin)) {
                return false;
            }

            if (!$this->pluginManager->isPluginEnabled($this->requiredPlugin)) {
                $this->pluginManager->enablePlugin($this->requiredPlugin);
            }

            return $this->isSatisfied();
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get configuration options for this dependency.
     *
     * @return array
     */
    public function getConfigOptions(): array
    {
        return [
            'required_plugin' => [
                'type' => 'string',
                'description' => 'The required plugin identifier',
                'required' => true,
            ],
            'minimum_version' => [
                'type' => 'string',
                'description' => 'Minimum version of the required plugin',
                'default' => '1.0.0',
            ]
        ];
    }
}