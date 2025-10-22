<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use function Laravel\Prompts\info;
use function Laravel\Prompts\table;

class WardenHelpCommand extends Command
{
    protected $signature = 'warden:help';
    
    protected $description = 'Show help information for all Warden commands';

    public function handle()
    {
        $this->info('Warden Security Audit - Help Guide');
        $this->line('');
        $this->line('Warden is a Laravel package that proactively monitors your dependencies for');
        $this->line('security vulnerabilities by running automated audits and sending notifications.');
        $this->line('');

        $this->info('Available Commands:');
        $this->line('');

        table(
            ['Command', 'Description'],
            [
                ['warden:audit', 'Run security audits on your application'],
                ['warden:schedule', 'Schedule automated security audits'],
                ['warden:syntax', 'Check PHP syntax in your application'],
                ['warden:plugin', 'Manage Warden plugins'],
                ['warden:help', 'Show this help information'],
            ]
        );

        $this->line('');
        $this->info('Command Details:');
        $this->line('');

        $this->section('warden:audit', [
            'Description: Run comprehensive security audits on your Laravel application',
            'Usage: php artisan warden:audit [options]',
            'Options:',
            '  --silent                    Run without sending notifications',
            '  --npm                       Include NPM package audit',
            '  --docker                    Include Docker security audit',
            '  --kubernetes                Include Kubernetes security audit',
            '  --git                       Include Git repository security audit',
            '  --security-patterns         Include security code patterns audit',
            '  --ignore-abandoned          Ignore abandoned packages',
            '  --output=FORMAT             Output format (json|github|gitlab|jenkins)',
            '  --severity=LEVEL            Filter by severity (low|medium|high|critical)',
            '  --force                     Force cache refresh',
            '',
            'Examples:',
            '  php artisan warden:audit                    # Run basic audits',
            '  php artisan warden:audit --git              # Include Git audit',
            '  php artisan warden:audit --npm --docker     # Include NPM and Docker audits',
            '  php artisan warden:audit --severity=high    # Only show high severity issues',
            '  php artisan warden:audit --output=json      # Output in JSON format',
        ]);

        $this->section('warden:schedule', [
            'Description: Schedule automated security audits to run at specified intervals',
            'Usage: php artisan warden:schedule',
            '',
            'This command sets up Laravel scheduler entries for automated audits.',
            'Configure scheduling in your config/warden.php file:',
            '  - frequency: hourly, daily, weekly, monthly',
            '  - time: Time of day to run (for daily/weekly/monthly)',
            '  - timezone: Custom timezone for scheduling',
            '',
            'Example configuration:',
            '  \'schedule\' => [',
            '      \'enabled\' => true,',
            '      \'frequency\' => \'daily\',',
            '      \'time\' => \'03:00\',',
            '  ],',
        ]);

        $this->section('warden:syntax', [
            'Description: Check PHP syntax across your application files',
            'Usage: php artisan warden:syntax [options]',
            'Options:',
            '  --path=PATH                Specific path to check (default: entire project)',
            '  --exclude=PATTERNS         Comma-separated patterns to exclude',
            '  --parallel                 Run checks in parallel for better performance',
            '',
            'Examples:',
            '  php artisan warden:syntax                   # Check entire project',
            '  php artisan warden:syntax --path=app        # Check only app directory',
            '  php artisan warden:syntax --exclude=vendor,tests  # Exclude directories',
        ]);

        $this->section('warden:plugin', [
            'Description: Manage Warden plugins for extending audit capabilities',
            'Usage: php artisan warden:plugin [action] [options]',
            'Actions:',
            '  list                       List all available plugins',
            '  enable PLUGIN              Enable a specific plugin',
            '  disable PLUGIN             Disable a specific plugin',
            '  info PLUGIN                Show detailed information about a plugin',
            '',
            'Examples:',
            '  php artisan warden:plugin list              # List all plugins',
            '  php artisan warden:plugin enable custom     # Enable custom plugin',
            '  php artisan warden:plugin info core-audit   # Show plugin details',
        ]);

        $this->line('');
        $this->info('Configuration:');
        $this->line('');
        $this->line('Warden can be configured through config/warden.php file or environment variables.');
        $this->line('Key configuration sections:');
        $this->line('  - notifications: Configure Slack, Discord, Email, Teams notifications');
        $this->line('  - cache: Configure audit result caching');
        $this->line('  - audits: Configure individual audit behaviors');
        $this->line('  - plugins: Configure plugin system');
        $this->line('  - schedule: Configure automated audit scheduling');
        $this->line('');

        $this->info('Environment Variables:');
        $this->line('');
        $this->line('Common environment variables for Warden:');
        $this->line('  WARDEN_SLACK_WEBHOOK_URL       Slack webhook URL');
        $this->line('  WARDEN_DISCORD_WEBHOOK_URL     Discord webhook URL');
        $this->line('  WARDEN_EMAIL_RECIPIENTS        Email recipients (comma-separated)');
        $this->line('  WARDEN_CACHE_ENABLED           Enable/disable caching');
        $this->line('  WARDEN_AUDIT_TIMEOUT           Audit timeout in seconds');
        $this->line('  WARDEN_SEVERITY_FILTER         Filter by severity level');
        $this->line('');

        $this->info('For more information, visit: https://github.com/dgtlss/warden');
        $this->line('');

        return 0;
    }

    private function section(string $title, array $lines)
    {
        $this->info($title);
        $this->line(str_repeat('-', strlen($title)));
        
        foreach ($lines as $line) {
            if (str_starts_with($line, '  ')) {
                $this->line($line);
            } elseif ($line === '') {
                $this->line('');
            } else {
                $this->line('  ' . $line);
            }
        }
        
        $this->line('');
    }
}