<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Dgtlss\Warden\Contracts\PluginManagerInterface;
use Dgtlss\Warden\Services\Dependencies\DependencyResolver;
use function Laravel\Prompts\{info, warning, error, table, confirm, text, select, multiselect};

class WardenPluginCommand extends Command
{
    protected $signature = 'warden:plugin 
                            {action : The action to perform (list, enable, disable, info, dependencies)}
                            {--plugin= : The plugin identifier (for enable/disable/info actions)}
                            {--all : Show all plugins including disabled ones}';

    protected $description = 'Manage Warden audit plugins';

    protected PluginManagerInterface $pluginManager;
    protected DependencyResolver $dependencyResolver;

    public function __construct(PluginManagerInterface $pluginManager, DependencyResolver $dependencyResolver)
    {
        parent::__construct();
        $this->pluginManager = $pluginManager;
        $this->dependencyResolver = $dependencyResolver;
    }

    public function handle(): int
    {
        $action = $this->argument('action');

        switch ($action) {
            case 'list':
                return $this->listPlugins();
            case 'enable':
                return $this->enablePlugin();
            case 'disable':
                return $this->disablePlugin();
            case 'info':
                return $this->showPluginInfo();
            case 'dependencies':
                return $this->showDependencies();
            default:
                $this->error("Unknown action: {$action}");
                $this->info('Available actions: list, enable, disable, info, dependencies');
                return 1;
        }
    }

    protected function listPlugins(): int
    {
        $showAll = $this->option('all');
        $plugins = $showAll ? $this->pluginManager->getPlugins() : $this->pluginManager->getEnabledPlugins();

        if (empty($plugins)) {
            $this->info($showAll ? 'No plugins registered.' : 'No enabled plugins found.');
            return 0;
        }

        $headers = ['Identifier', 'Name', 'Version', 'Author', 'Status', 'Audits'];
        $rows = [];

        foreach ($plugins as $identifier => $plugin) {
            $status = $this->pluginManager->isPluginEnabled($identifier) ? '✅ Enabled' : '❌ Disabled';
            $auditCount = count($plugin->getAuditClasses());
            
            $rows[] = [
                $identifier,
                $plugin->getName(),
                $plugin->getVersion(),
                $plugin->getAuthor(),
                $status,
                $auditCount
            ];
        }

        table($headers, $rows);

        $this->info("\nTotal plugins: " . count($plugins));
        
        if (!$showAll) {
            $totalPlugins = count($this->pluginManager->getPlugins());
            $disabledCount = $totalPlugins - count($plugins);
            if ($disabledCount > 0) {
                $this->info("Disabled plugins: {$disabledCount} (use --all to see them)");
            }
        }

        return 0;
    }

    protected function enablePlugin(): int
    {
        $pluginId = $this->getPluginIdentifier();
        
        if (!$pluginId) {
            return 1;
        }

        if ($this->pluginManager->isPluginEnabled($pluginId)) {
            $this->info("Plugin '{$pluginId}' is already enabled.");
            return 0;
        }

        try {
            $this->pluginManager->enablePlugin($pluginId);
            $this->info("Plugin '{$pluginId}' has been enabled successfully.");
            return 0;
        } catch (\Exception $e) {
            $this->error("Failed to enable plugin '{$pluginId}': " . $e->getMessage());
            return 1;
        }
    }

    protected function disablePlugin(): int
    {
        $pluginId = $this->getPluginIdentifier();
        
        if (!$pluginId) {
            return 1;
        }

        if (!$this->pluginManager->isPluginEnabled($pluginId)) {
            $this->info("Plugin '{$pluginId}' is already disabled.");
            return 0;
        }

        try {
            $this->pluginManager->disablePlugin($pluginId);
            $this->info("Plugin '{$pluginId}' has been disabled successfully.");
            return 0;
        } catch (\Exception $e) {
            $this->error("Failed to disable plugin '{$pluginId}': " . $e->getMessage());
            return 1;
        }
    }

    protected function showPluginInfo(): int
    {
        $pluginId = $this->getPluginIdentifier();
        
        if (!$pluginId) {
            return 1;
        }

        $plugin = $this->pluginManager->getPlugin($pluginId);
        
        if (!$plugin) {
            $this->error("Plugin '{$pluginId}' not found.");
            return 1;
        }

        $this->line("\n<options=bold>Plugin Information</>");
        $this->line("Identifier: {$plugin->getIdentifier()}");
        $this->line("Name: {$plugin->getName()}");
        $this->line("Version: {$plugin->getVersion()}");
        $this->line("Author: {$plugin->getAuthor()}");
        $this->line("Description: {$plugin->getDescription()}");
        $this->line("Status: " . ($this->pluginManager->isPluginEnabled($pluginId) ? '✅ Enabled' : '❌ Disabled'));
        
        // Dependencies
        $dependencies = $plugin->getDependencies();
        if (!empty($dependencies)) {
            $this->line("\n<options=bold>Dependencies:</>");
            foreach ($dependencies as $dep) {
                $status = $this->pluginManager->isPluginEnabled($dep) ? '✅' : '❌';
                $this->line("  {$status} {$dep}");
            }
        } else {
            $this->line("\n<options=bold>Dependencies:</> None");
        }

        // Audit Classes
        $auditClasses = $plugin->getAuditClasses();
        if (!empty($auditClasses)) {
            $this->line("\n<options=bold>Audit Classes:</>");
            foreach ($auditClasses as $class) {
                $className = class_basename($class);
                $this->line("  • {$className} ({$class})");
            }
        } else {
            $this->line("\n<options=bold>Audit Classes:</> None");
        }

        // Configuration
        $config = $this->pluginManager->getPluginConfig($pluginId);
        $this->line("\n<options=bold>Configuration:</>");
        foreach ($config as $key => $value) {
            $displayValue = is_bool($value) ? ($value ? 'true' : 'false') : $value;
            $this->line("  {$key}: {$displayValue}");
        }

        return 0;
    }

    protected function showDependencies(): int
    {
        $report = $this->dependencyResolver->getResolutionReport();

        $this->line("\n<options=bold>Dependency Resolution Report</>");
        $this->line("Total dependencies: {$report['total']}");
        $this->line("Satisfied: {$report['satisfied']}");
        $this->line("Unsatisfied: {$report['unsatisfied']}");
        $this->line("Resolvable: {$report['resolvable']}");
        $this->line("Unresolvable: {$report['unresolvable']}");

        if (!empty($report['details'])) {
            $headers = ['Identifier', 'Type', 'Priority', 'Satisfied', 'Resolvable', 'Reason'];
            $rows = [];

            foreach ($report['details'] as $id => $detail) {
                $rows[] = [
                    $id,
                    $detail['type'],
                    $detail['priority'],
                    $detail['satisfied'] ? '✅' : '❌',
                    $detail['resolvable'] ? '✅' : '❌',
                    $detail['reason'] ?? 'N/A'
                ];
            }

            $this->line("\n<options=bold>Dependency Details:</>");
            table($headers, $rows);
        }

        // Attempt to resolve dependencies if requested
        if ($report['unsatisfied'] > 0 && confirm('Attempt to resolve unsatisfied dependencies?')) {
            $results = $this->dependencyResolver->resolveAll();
            
            $resolved = 0;
            $failed = 0;
            
            foreach ($results as $id => $success) {
                if ($success) {
                    $resolved++;
                } else {
                    $failed++;
                }
            }

            $this->info("\nResolution Results:");
            $this->line("Successfully resolved: {$resolved}");
            $this->line("Failed to resolve: {$failed}");
        }

        return 0;
    }

    protected function getPluginIdentifier(): ?string
    {
        $pluginId = $this->option('plugin');
        
        if (!$pluginId) {
            $plugins = $this->pluginManager->getPlugins();
            
            if (empty($plugins)) {
                $this->error('No plugins registered.');
                return null;
            }

            $choices = [];
            foreach ($plugins as $id => $plugin) {
                $choices[$id] = "{$plugin->getName()} ({$id})";
            }

            $pluginId = select(
                'Select a plugin:',
                $choices
            );
        }

        return $pluginId;
    }
}