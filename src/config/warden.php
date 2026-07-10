<?php

declare(strict_types=1);

return [
    'app_name' => env('WARDEN_APP_NAME', config('app.name', 'Application')),

    'audits' => [
        'timeout' => (int) env('WARDEN_AUDIT_TIMEOUT', 300),
        'php_syntax' => [
            'exclude' => [
                'vendor',
                'node_modules',
                'storage',
                'bootstrap/cache',
                '.git',
            ],
        ],
        'source' => [
            'php_paths' => ['app', 'bootstrap', 'config', 'routes'],
            'blade_paths' => ['resources/views'],
            'exclude' => [
                'vendor',
                'node_modules',
                'storage',
                'bootstrap/cache',
                'tests',
                'database',
                'public/build',
                '.git',
            ],
            'max_file_size_kb' => 1024,
        ],
        'supply_chain' => [
            'minimum_release_age_days' => 3,
        ],
        'platform' => [
            'warning_days' => 90,
        ],
    ],

    /*
    | Every suppression must be reviewed and time-limited. Add fingerprint to
    | suppress only one concrete occurrence of a rule.
    */
    'ignore_findings' => [
        // [
        //     'id' => 'composer.advisory.ghsa-example',
        //     'fingerprint' => 'optional-fingerprint',
        //     'reason' => 'Compensating control reviewed in SEC-123',
        //     'expires_at' => '2099-12-31',
        // ],
    ],

    'baseline' => [
        'file' => env('WARDEN_BASELINE_FILE', 'warden-baseline.json'),
    ],

    /* Override a built-in rule with enforced, advisory, or off. */
    'rule_overrides' => [
        // 'source.blade.unescaped-output' => 'enforced',
    ],

    'custom_audits' => [
        // \App\Audits\MyCustomAudit::class,
    ],

    'notifications' => [
        'slack' => ['webhook_url' => env('WARDEN_SLACK_WEBHOOK_URL')],
        'discord' => ['webhook_url' => env('WARDEN_DISCORD_WEBHOOK_URL')],
        'teams' => ['webhook_url' => env('WARDEN_TEAMS_WEBHOOK_URL')],
        'email' => [
            'recipients' => env('WARDEN_EMAIL_RECIPIENTS'),
            'from_address' => env('WARDEN_EMAIL_FROM', config('mail.from.address')),
            'from_name' => env('WARDEN_EMAIL_FROM_NAME', 'Warden Security'),
        ],
    ],
];
