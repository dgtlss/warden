<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use function Laravel\Prompts\info;
use function Laravel\Prompts\table;

class WardenConfigCommand extends Command
{
    protected $signature = 'warden:config 
                            {--show-env : Show environment variable values}
                            {--service= : Show configuration for specific service}';

    protected $description = 'Display current Warden configuration and effective settings';

    public function handle(): int
    {
        $this->info('Warden Configuration');
        $this->line('==================');
        $this->newLine();

        // Show core settings
        $this->displayCoreSettings();

        // Show mode configurations
        $this->displayModeConfigurations();

        // Show service configurations
        if ($service = $this->option('service')) {
            $this->displayServiceConfiguration($service);
        } else {
            $this->displayAllServiceConfigurations();
        }

        // Show notification channels
        $this->displayNotificationChannels();

        // Show auto-discovery status
        $this->displayAutoDiscoveryStatus();

        return 0;
    }

    protected function displayCoreSettings(): void
    {
        $this->info('Core Settings:');
        $headers = ['Setting', 'Value', 'Environment Variable'];
        $rows = [];

        $rows[] = [
            'Default Mode',
            config('warden.default_mode', 'ci'),
            'WARDEN_DEFAULT_MODE'
        ];

        $rows[] = [
            'Cache Enabled',
            config('warden.cache_enabled', false) ? 'Yes' : 'No',
            'WARDEN_CACHE_ENABLED'
        ];

        $rows[] = [
            'Notifications Enabled',
            config('warden.notifications_enabled', false) ? 'Yes' : 'No',
            'WARDEN_NOTIFICATIONS_ENABLED'
        ];

        table($headers, $rows);
        $this->newLine();
    }

    protected function displayModeConfigurations(): void
    {
        $this->info('Mode Configurations:');
        
        foreach (['ci', 'full'] as $mode) {
            $config = config("warden.{$mode}", []);
            $this->line("{$mode}:");
            $this->line("  Timeout: {$config['timeout']} seconds");
            $this->line("  Services: " . implode(', ', $config['services']));
            $this->line("  Parallel: " . ($config['parallel'] ? 'Yes' : 'No'));
            $this->line("  Cache: " . ($config['cache'] ? 'Yes' : 'No'));
            $this->line("  Notifications: " . ($config['notifications'] ? 'Yes' : 'No'));
            $this->newLine();
        }
    }

    protected function displayAllServiceConfigurations(): void
    {
        $this->info('Service Configurations:');
        
        $services = [
            'composer' => 'Composer Audit',
            'npm' => 'NPM Audit',
            'docker' => 'Docker Audit',
            'kubernetes' => 'Kubernetes Audit',
            'git' => 'Git Audit',
            'env' => 'Environment Audit',
            'storage' => 'Storage Audit',
            'debug' => 'Debug Mode Audit',
            'security_patterns' => 'Security Patterns Audit',
            'php_syntax' => 'PHP Syntax Audit',
        ];

        foreach ($services as $key => $name) {
            $this->displayServiceConfiguration($key, $name, false);
        }
    }

    protected function displayServiceConfiguration(string $service, string $name = null, bool $detailed = true): void
    {
        $name = $name ?? ucfirst($service) . ' Audit';
        $config = config("warden.audits.{$service}", []);

        if (empty($config)) {
            $this->line("{$name}: No specific configuration (using defaults)");
            if ($detailed) $this->newLine();
            return;
        }

        $this->line("{$name}:");
        
        if ($detailed) {
            foreach ($config as $key => $value) {
                if (is_array($value)) {
                    $value = implode(', ', $value);
                } elseif (is_bool($value)) {
                    $value = $value ? 'Yes' : 'No';
                }
                $this->line("  {$key}: {$value}");
            }
        } else {
            $this->line("  Configured: Yes");
        }
        
        if ($detailed) $this->newLine();
    }

    protected function displayNotificationChannels(): void
    {
        $this->info('Notification Channels:');
        $channels = config('warden.notifications.channels', []);

        if (empty($channels)) {
            $this->line('No notification channels configured');
        } else {
            foreach ($channels as $channel) {
                $this->line("  {$channel}: Enabled");
            }
        }

        $this->newLine();
    }

    protected function displayAutoDiscoveryStatus(): void
    {
        $this->info('Auto-Discovery Status:');
        $autoDiscover = config('warden.auto_discover', []);

        foreach ($autoDiscover as $service => $enabled) {
            $status = $enabled ? 'Available' : 'Not Available';
            $this->line("  {$service}: {$status}");
        }

        $this->newLine();
    }
}