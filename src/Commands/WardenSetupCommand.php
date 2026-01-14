<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use function Laravel\Prompts\confirm;
use function Laravel\Prompts\error;
use function Laravel\Prompts\info;
use function Laravel\Prompts\multiselect;
use function Laravel\Prompts\note;
use function Laravel\Prompts\select;
use function Laravel\Prompts\text;
use function Laravel\Prompts\warning;

class WardenSetupCommand extends Command
{
    protected $signature = 'warden:setup
        {--show-env : Only display recommended .env values without prompts}';

    protected $description = 'Interactive setup wizard for configuring Warden security audits.';

    /**
     * @var array<string, string|bool|null>
     */
    protected array $config = [];

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->displayWelcome();

        if ($this->option('show-env')) {
            return $this->showEnvValues();
        }

        $this->setupNotificationChannels();
        $this->setupCacheSettings();
        $this->setupScheduleSettings();
        $this->setupSecuritySettings();
        $this->setupAdvancedSettings();

        $this->displaySummary();

        return 0;
    }

    /**
     * Display welcome message.
     */
    protected function displayWelcome(): void
    {
        info('Welcome to Warden Security Setup!');
        note('This wizard will help you configure Warden for your Laravel application.');
        $this->newLine();
    }

    /**
     * Show recommended .env values.
     */
    protected function showEnvValues(): int
    {
        note('Add these values to your .env file:');
        $this->newLine();

        $envValues = [
            '# Warden Security Configuration',
            '# ================================',
            '',
            '# Notification Channels',
            'WARDEN_SLACK_WEBHOOK_URL=',
            'WARDEN_DISCORD_WEBHOOK_URL=',
            'WARDEN_TEAMS_WEBHOOK_URL=',
            'WARDEN_EMAIL_RECIPIENTS=',
            '',
            '# Cache Settings',
            'WARDEN_CACHE_ENABLED=true',
            'WARDEN_CACHE_DURATION=3600',
            '',
            '# Scheduling',
            'WARDEN_SCHEDULE_ENABLED=false',
            'WARDEN_SCHEDULE_FREQUENCY=daily',
            'WARDEN_SCHEDULE_TIME=03:00',
            '',
            '# Security',
            'WARDEN_WEBHOOK_SIGNING_ENABLED=false',
            'WARDEN_WEBHOOK_SECRET=',
            'WARDEN_RATE_LIMIT_ENABLED=false',
            'WARDEN_RATE_LIMIT_MAX_ATTEMPTS=10',
            '',
            '# Queue Processing',
            'WARDEN_QUEUE_ENABLED=true',
            'WARDEN_QUEUE_CONNECTION=',
            'WARDEN_QUEUE_NAME=default',
            '',
            '# Audit History',
            'WARDEN_HISTORY_ENABLED=false',
            'WARDEN_HISTORY_RETENTION_DAYS=90',
            '',
            '# Incremental Audits',
            'WARDEN_INCREMENTAL_ENABLED=false',
        ];

        foreach ($envValues as $line) {
            $this->line($line);
        }

        return 0;
    }

    /**
     * Setup notification channels.
     */
    protected function setupNotificationChannels(): void
    {
        info('Step 1: Notification Channels');

        /** @var array<string> $channels */
        $channels = multiselect(
            label: 'Which notification channels do you want to configure?',
            options: [
                'slack' => 'Slack',
                'discord' => 'Discord',
                'teams' => 'Microsoft Teams',
                'email' => 'Email',
            ],
            hint: 'Select one or more channels',
        );

        if (in_array('slack', $channels, true)) {
            $this->config['WARDEN_SLACK_WEBHOOK_URL'] = text(
                label: 'Slack Webhook URL',
                placeholder: 'https://hooks.slack.com/services/...',
                hint: 'Leave empty to skip Slack configuration',
            );
        }

        if (in_array('discord', $channels, true)) {
            $this->config['WARDEN_DISCORD_WEBHOOK_URL'] = text(
                label: 'Discord Webhook URL',
                placeholder: 'https://discord.com/api/webhooks/...',
                hint: 'Leave empty to skip Discord configuration',
            );
        }

        if (in_array('teams', $channels, true)) {
            $this->config['WARDEN_TEAMS_WEBHOOK_URL'] = text(
                label: 'Microsoft Teams Webhook URL',
                placeholder: 'https://outlook.office.com/webhook/...',
                hint: 'Leave empty to skip Teams configuration',
            );
        }

        if (in_array('email', $channels, true)) {
            $this->config['WARDEN_EMAIL_RECIPIENTS'] = text(
                label: 'Email Recipients',
                placeholder: 'security@example.com,admin@example.com',
                hint: 'Comma-separated list of email addresses',
            );
        }

        $this->newLine();
    }

    /**
     * Setup cache settings.
     */
    protected function setupCacheSettings(): void
    {
        info('Step 2: Cache Settings');

        $enableCache = confirm(
            label: 'Enable caching for audit results?',
            default: true,
            hint: 'Caching prevents running audits too frequently',
        );

        $this->config['WARDEN_CACHE_ENABLED'] = $enableCache;

        if ($enableCache) {
            /** @var string $cacheDuration */
            $cacheDuration = select(
                label: 'How long should results be cached?',
                options: [
                    '1800' => '30 minutes',
                    '3600' => '1 hour',
                    '7200' => '2 hours',
                    '21600' => '6 hours',
                    '86400' => '24 hours',
                ],
                default: '3600',
            );

            $this->config['WARDEN_CACHE_DURATION'] = $cacheDuration;
        }

        $this->newLine();
    }

    /**
     * Setup schedule settings.
     */
    protected function setupScheduleSettings(): void
    {
        info('Step 3: Scheduled Audits');

        $enableSchedule = confirm(
            label: 'Enable automated scheduled audits?',
            default: false,
            hint: 'Run audits automatically on a schedule',
        );

        $this->config['WARDEN_SCHEDULE_ENABLED'] = $enableSchedule;

        if ($enableSchedule) {
            /** @var string $frequency */
            $frequency = select(
                label: 'How often should audits run?',
                options: [
                    'hourly' => 'Every hour',
                    'daily' => 'Daily',
                    'weekly' => 'Weekly',
                    'monthly' => 'Monthly',
                ],
                default: 'daily',
            );

            $this->config['WARDEN_SCHEDULE_FREQUENCY'] = $frequency;

            if ($frequency !== 'hourly') {
                $scheduleTime = text(
                    label: 'What time should the audit run?',
                    placeholder: '03:00',
                    default: '03:00',
                    hint: 'Use 24-hour format (HH:MM)',
                );

                $this->config['WARDEN_SCHEDULE_TIME'] = $scheduleTime;
            }
        }

        $this->newLine();
    }

    /**
     * Setup security settings.
     */
    protected function setupSecuritySettings(): void
    {
        info('Step 4: Security Settings');

        $enableRateLimit = confirm(
            label: 'Enable rate limiting for audit commands?',
            default: false,
            hint: 'Prevents abuse by limiting how often audits can run',
        );

        $this->config['WARDEN_RATE_LIMIT_ENABLED'] = $enableRateLimit;

        if ($enableRateLimit) {
            $maxAttempts = text(
                label: 'Maximum audit attempts per hour',
                placeholder: '10',
                default: '10',
            );

            $this->config['WARDEN_RATE_LIMIT_MAX_ATTEMPTS'] = $maxAttempts;
        }

        $enableWebhookSigning = confirm(
            label: 'Enable webhook signature verification?',
            default: false,
            hint: 'Signs outgoing webhook requests with HMAC-SHA256',
        );

        $this->config['WARDEN_WEBHOOK_SIGNING_ENABLED'] = $enableWebhookSigning;

        if ($enableWebhookSigning) {
            $secret = text(
                label: 'Webhook signing secret',
                placeholder: 'your-secret-key',
                hint: 'A secure random string for signing webhooks',
            );

            if ($secret !== '') {
                $this->config['WARDEN_WEBHOOK_SECRET'] = $secret;
            } else {
                warning('Webhook signing is enabled but no secret was provided.');
                note('Generate a secret with: php artisan key:generate --show');
            }
        }

        $this->newLine();
    }

    /**
     * Setup advanced settings.
     */
    protected function setupAdvancedSettings(): void
    {
        info('Step 5: Advanced Settings');

        $enableQueue = confirm(
            label: 'Enable background queue processing?',
            default: true,
            hint: 'Run audits in the background using Laravel queues',
        );

        $this->config['WARDEN_QUEUE_ENABLED'] = $enableQueue;

        if ($enableQueue) {
            /** @var string $queueName */
            $queueName = text(
                label: 'Queue name for audit jobs',
                placeholder: 'default',
                default: 'default',
            );

            $this->config['WARDEN_QUEUE_NAME'] = $queueName;
        }

        $enableHistory = confirm(
            label: 'Enable audit history tracking?',
            default: false,
            hint: 'Store audit results in the database for trending',
        );

        $this->config['WARDEN_HISTORY_ENABLED'] = $enableHistory;

        if ($enableHistory) {
            /** @var string $retentionDays */
            $retentionDays = select(
                label: 'How long should audit history be retained?',
                options: [
                    '30' => '30 days',
                    '60' => '60 days',
                    '90' => '90 days',
                    '180' => '180 days',
                    '365' => '1 year',
                ],
                default: '90',
            );

            $this->config['WARDEN_HISTORY_RETENTION_DAYS'] = $retentionDays;

            note('Run "php artisan migrate" to create the audit history table.');
        }

        $enableIncremental = confirm(
            label: 'Enable incremental audits?',
            default: false,
            hint: 'Only scan changed dependencies for faster audits',
        );

        $this->config['WARDEN_INCREMENTAL_ENABLED'] = $enableIncremental;

        $this->newLine();
    }

    /**
     * Display configuration summary.
     */
    protected function displaySummary(): void
    {
        info('Configuration Complete!');
        $this->newLine();

        note('Add the following to your .env file:');
        $this->newLine();

        foreach ($this->config as $key => $value) {
            if ($value === null || $value === '') {
                continue;
            }

            $displayValue = is_bool($value) ? ($value ? 'true' : 'false') : $value;
            $this->line("{$key}={$displayValue}");
        }

        $this->newLine();

        info('Next steps:');
        $this->line('  1. Copy the above values to your .env file');
        $this->line('  2. Run "php artisan config:cache" to apply changes');
        $this->line('  3. Test with "php artisan warden:audit --dry-run"');

        if ($this->config['WARDEN_HISTORY_ENABLED'] ?? false) {
            $this->line('  4. Run "php artisan migrate" to create audit history table');
        }

        $this->newLine();
        info('Run "php artisan warden:audit" to start your first security scan!');
    }
}
