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
    | Active Profile
    |--------------------------------------------------------------------------
    |
    | Warden v2 introduces audit profiles so stronger rulesets can be adopted
    | without breaking existing CI pipelines. "legacy" preserves v1 behavior.
    |
    */

    'profile' => 'legacy',

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
        'max_concurrency' => env('WARDEN_MAX_CONCURRENCY', 4),
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
    | Profile Definitions
    |--------------------------------------------------------------------------
    */

    'profiles' => [
        'legacy' => [
            'description' => 'Preserves the original Warden audit footprint for existing users.',
        ],
        'recommended' => [
            'description' => 'CI-first security profile with additional repository and Laravel posture checks.',
        ],
        'ci-strict' => [
            'description' => 'Most comprehensive CI profile for security-focused pipelines.',
        ],
        'runtime-safe' => [
            'description' => 'Application-safe profile intended for scheduled and in-environment audits.',
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
    | Baseline And Policy Configuration
    |--------------------------------------------------------------------------
    */

    'baseline' => [
        'enabled' => true,
        'path' => '.warden-baseline.json',
    ],

    'policy' => [
        'suppressions' => [
            // [
            //     'fingerprint' => 'sha256...',
            //     'reason' => 'Accepted until dependency upgrade lands.',
            //     'expires_at' => '2026-12-31T00:00:00+00:00',
            // ],
        ],
        'composer' => [
            'include_dev_dependencies' => true,
        ],
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
        'enabled' => false,
        'table' => 'warden_audit_history',
        'retention_days' => 90,
    ],

    /*
    |--------------------------------------------------------------------------
    | CI Integrations
    |--------------------------------------------------------------------------
    |
    | These values are optional manual overrides. Warden still detects runtime
    | CI context directly from GitHub, GitLab, and Jenkins environment
    | variables when the package is running inside a pipeline.
    */

    'integrations' => [
        'github' => [
            'repository' => null,
        ],
        'gitlab' => [
            'project' => null,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Warden Cloud
    |--------------------------------------------------------------------------
    |
    | Core Warden remains fully offline-capable. These settings activate the
    | optional cloud sync path when you are ready to layer on hosted features.
    |
    */

    'cloud' => [
        'enabled' => false,
        'base_url' => null,
        'token' => null,
        'auto_sync' => false,
        'fail_closed' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Auto Resolve
    |--------------------------------------------------------------------------
    |
    | Warden resolve is intentionally conservative in v1 and focuses on
    | dependency-level remediations that can be previewed and explained before
    | being applied.
    |
    */

    'resolve' => [
        'enabled' => true,
        'allow_in_ci' => false,
        'default_verify' => true,
        'allow_dirty' => false,
        'auto_branch' => false,
        'package_managers' => [
            'composer' => true,
            'npm' => true,
            'pnpm' => true,
            'yarn' => true,
        ],
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
