<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Application Name
    |--------------------------------------------------------------------------
    |
    | Configure the name of your application to be included in notifications.
    | This helps distinguish between different applications when running Warden
    | across multiple projects.
    |
    */

    'app_name' => env('WARDEN_APP_NAME', config('app.name', 'Application')),

    /*
    |--------------------------------------------------------------------------
    | Notification Settings
    |--------------------------------------------------------------------------
    |
    | Configure where Warden should send security audit notifications.
    | Multiple notification channels are supported:
    | - Legacy webhook_url for backward compatibility
    | - Email recipients
    | - Slack, Discord, Microsoft Teams webhooks
    |
    */

    'webhook_url' => env('WARDEN_WEBHOOK_URL'), // Legacy support
    'email_recipients' => env('WARDEN_EMAIL_RECIPIENTS'),

    'notifications' => [
        'slack' => [
            'webhook_url' => env('WARDEN_SLACK_WEBHOOK_URL', env('WARDEN_WEBHOOK_URL')),
        ],
        'discord' => [
            'webhook_url' => env('WARDEN_DISCORD_WEBHOOK_URL'),
        ],
        'teams' => [
            'webhook_url' => env('WARDEN_TEAMS_WEBHOOK_URL'),
        ],
        'email' => [
            'recipients' => env('WARDEN_EMAIL_RECIPIENTS'),
            'from_address' => env('WARDEN_EMAIL_FROM', config('mail.from.address')),
            'from_name' => env('WARDEN_EMAIL_FROM_NAME', 'Warden Security'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Configuration
    |--------------------------------------------------------------------------
    |
    | Configure caching behavior for audit results to prevent running
    | audits too frequently. This helps with rate limiting and performance.
    |
    */

    'cache' => [
        'enabled' => env('WARDEN_CACHE_ENABLED', true),
        'duration' => env('WARDEN_CACHE_DURATION', 3600), // seconds (default: 1 hour)
        'driver' => env('WARDEN_CACHE_DRIVER', config('cache.default')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit Configuration
    |--------------------------------------------------------------------------
    |
    | Configure audit behavior and filtering options.
    |
    */

    'audits' => [
        'parallel_execution' => env('WARDEN_PARALLEL_EXECUTION', true),
        'timeout' => env('WARDEN_AUDIT_TIMEOUT', 300), // seconds
        'php_syntax' => [
            'enabled' => env('WARDEN_PHP_SYNTAX_AUDIT_ENABLED', false),
            'exclude' => [
                'vendor',
                'node_modules',
                'storage',
                'bootstrap/cache',
                '.git',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Audits
    |--------------------------------------------------------------------------
    |
    | Register your custom audit classes here. Each class must implement
    | the Dgtlss\Warden\Contracts\CustomAudit interface.
    |
    */

    'custom_audits' => [
        // \App\Audits\MyCustomAudit::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Scheduling Configuration
    |--------------------------------------------------------------------------
    |
    | Configure automated audit scheduling. Set to false to disable.
    |
    */

    'schedule' => [
        'enabled' => env('WARDEN_SCHEDULE_ENABLED', false),
        'frequency' => env('WARDEN_SCHEDULE_FREQUENCY', 'daily'), // hourly|daily|weekly|monthly
        'time' => env('WARDEN_SCHEDULE_TIME', '03:00'), // Time in 24h format
        'timezone' => env('WARDEN_SCHEDULE_TIMEZONE', config('app.timezone')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit History
    |--------------------------------------------------------------------------
    |
    | Configure database storage for audit history tracking.
    |
    */

    'history' => [
        'enabled' => env('WARDEN_HISTORY_ENABLED', false),
        'table' => env('WARDEN_HISTORY_TABLE', 'warden_audit_history'),
        'retention_days' => env('WARDEN_HISTORY_RETENTION_DAYS', 90),
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Audit Configuration
    |--------------------------------------------------------------------------
    |
    | Define environment variables that should be checked during security audits.
    | These keys are considered security-critical and should be properly set
    | in your production environment.
    |
    | Add your own sensitive keys based on your application's requirements.
    | The check will fail if these keys are missing from your .env file,
    | encouraging proper security configuration from the start.
    |
    | Example key formats:
    | - Database: DB_PASSWORD
    | - Email: SMTP_PASSWORD, MAILGUN_SECRET
    | - Payment: STRIPE_SECRET_KEY, PAYPAL_SECRET
    | - Cloud: AWS_SECRET_KEY, GOOGLE_CLOUD_KEY
    |
    */
   
    'sensitive_keys' => [
       // Add your sensitive keys here
    ],
];
