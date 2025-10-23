<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Warden Security Audit Configuration
    |--------------------------------------------------------------------------
    */

    /*
    |--------------------------------------------------------------------------
    | Core Settings
    |--------------------------------------------------------------------------
    */

    'default_mode' => env('WARDEN_DEFAULT_MODE', 'ci'), // ci|full
    'cache_enabled' => env('WARDEN_CACHE_ENABLED', false),
    'notifications_enabled' => env('WARDEN_NOTIFICATIONS_ENABLED', false),

    /*
    |--------------------------------------------------------------------------
    | Mode Configurations
    |--------------------------------------------------------------------------
    |
    | Pre-configured settings for different operation modes.
    |
    */

    'ci' => [
        'timeout' => env('WARDEN_CI_TIMEOUT', 120),
        'services' => ['composer', 'env', 'debug'],
        'parallel' => false,
        'cache' => false,
        'notifications' => false,
    ],

    'full' => [
        'timeout' => env('WARDEN_FULL_TIMEOUT', 300),
        'services' => ['composer', 'env', 'storage', 'debug', 'npm', 'docker', 'kubernetes', 'git', 'security_patterns'],
        'parallel' => env('WARDEN_PARALLEL_EXECUTION', true),
        'cache' => env('WARDEN_CACHE_ENABLED', true),
        'notifications' => env('WARDEN_NOTIFICATIONS_ENABLED', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Notification Channels
    |--------------------------------------------------------------------------
    |
    | Auto-discovered from environment variables. Channels are only enabled
    | if their respective environment variables are set.
    |
    */

    'notifications' => [
        'channels' => array_filter([
            env('WARDEN_SLACK_WEBHOOK_URL') ? 'slack' : null,
            env('WARDEN_DISCORD_WEBHOOK_URL') ? 'discord' : null,
            env('WARDEN_TEAMS_WEBHOOK_URL') ? 'teams' : null,
            env('WARDEN_EMAIL_RECIPIENTS') ? 'email' : null,
        ]),

        'slack' => [
            'webhook_url' => env('WARDEN_SLACK_WEBHOOK_URL'),
            'channel' => env('WARDEN_SLACK_CHANNEL', '#security'),
            'username' => env('WARDEN_SLACK_USERNAME', 'Warden'),
            'icon_emoji' => ':shield:',
        ],

        'discord' => [
            'webhook_url' => env('WARDEN_DISCORD_WEBHOOK_URL'),
            'username' => env('WARDEN_DISCORD_USERNAME', 'Warden'),
        ],

        'teams' => [
            'webhook_url' => env('WARDEN_TEAMS_WEBHOOK_URL'),
            'title' => 'Warden Security Audit',
        ],

        'email' => [
            'recipients' => env('WARDEN_EMAIL_RECIPIENTS'),
            'from_address' => env('WARDEN_EMAIL_FROM', config('mail.from.address')),
            'from_name' => env('WARDEN_EMAIL_FROM_NAME', 'Warden Security'),
            'template' => 'warden::mail.report',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Service Auto-Discovery
    |--------------------------------------------------------------------------
    |
    | Automatically enable services based on project structure.
    |
    */

    'auto_discover' => [
        'npm' => file_exists(base_path('package.json')),
        'docker' => file_exists(base_path('Dockerfile')) || file_exists(base_path('docker-compose.yml')),
        'kubernetes' => collect([
            'k8s/', 'kubernetes/', 'deploy/', 'manifests/',
            '*.yaml', '*.yml'
        ])->filter(fn($path) => file_exists(base_path($path)) || glob(base_path($path)))->isNotEmpty(),
        'git' => true, // Always available in git repositories
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Configuration
    |--------------------------------------------------------------------------
    */

    'cache' => [
        'duration' => env('WARDEN_CACHE_DURATION', 3600), // 1 hour
        'driver' => env('WARDEN_CACHE_DRIVER', config('cache.default')),
        'prefix' => 'warden_audit',
    ],

    /*
    |--------------------------------------------------------------------------
    | Scheduling
    |--------------------------------------------------------------------------
    */

    'schedule' => [
        'enabled' => env('WARDEN_SCHEDULE_ENABLED', false),
        'frequency' => env('WARDEN_SCHEDULE_FREQUENCY', 'daily'),
        'time' => env('WARDEN_SCHEDULE_TIME', '03:00'),
        'timezone' => env('WARDEN_SCHEDULE_TIMEZONE', config('app.timezone')),
        'silent' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Audits
    |--------------------------------------------------------------------------
    */

    'custom_audits' => env('WARDEN_CUSTOM_AUDITS') 
        ? explode(',', env('WARDEN_CUSTOM_AUDITS')) 
        : [],

    /*
    |--------------------------------------------------------------------------
    | Backward Compatibility
    |--------------------------------------------------------------------------
    |
    | Legacy configuration support for existing installations.
    | These will be phased out in future versions.
    |
    */

    // Legacy support - maintained for backward compatibility
    'webhook_url' => env('WARDEN_WEBHOOK_URL', null),
    'email_recipients' => env('WARDEN_EMAIL_RECIPIENTS', null),

    // Legacy audit configurations (mapped to new structure)
    'audits' => [
        'parallel_execution' => env('WARDEN_PARALLEL_EXECUTION', true),
        'timeout' => env('WARDEN_AUDIT_TIMEOUT', 300),
        'retry_attempts' => env('WARDEN_RETRY_ATTEMPTS', 3),
        'severity_filter' => env('WARDEN_SEVERITY_FILTER', null),
        
        // Backward compatibility: Individual audit configurations
        // These are now handled by environment variables in each service class
        'composer' => [
            'ignore_abandoned' => env('WARDEN_COMPOSER_IGNORE_ABANDONED', false),
            'format' => env('WARDEN_COMPOSER_FORMAT', 'json'),
            'working_directory' => env('WARDEN_COMPOSER_WORKING_DIRECTORY', base_path()),
            'timeout' => env('WARDEN_COMPOSER_TIMEOUT', 300),
            'no_dev' => env('WARDEN_COMPOSER_NO_DEV', true),
        ],
        'npm' => [
            'format' => env('WARDEN_NPM_FORMAT', 'json'),
            'working_directory' => env('WARDEN_NPM_WORKING_DIRECTORY', base_path()),
            'require_lockfile' => env('WARDEN_NPM_REQUIRE_LOCKFILE', true),
            'timeout' => env('WARDEN_NPM_TIMEOUT', 300),
            'production_only' => env('WARDEN_NPM_PRODUCTION_ONLY', false),
            'audit_level' => env('WARDEN_NPM_AUDIT_LEVEL', 'moderate'),
        ],
        'docker' => [
            'dockerfile_path' => env('WARDEN_DOCKERFILE_PATH', 'Dockerfile'),
            'docker_compose_path' => env('WARDEN_DOCKER_COMPOSE_PATH', 'docker-compose.yml'),
            'scan_images' => env('WARDEN_DOCKER_SCAN_IMAGES', true),
            'scan_dockerfile' => env('WARDEN_DOCKER_SCAN_DOCKERFILE', true),
            'scan_docker_compose' => env('WARDEN_DOCKER_SCAN_DOCKER_COMPOSE', true),
            'check_base_images' => env('WARDEN_DOCKER_CHECK_BASE_IMAGES', true),
            'check_secrets' => env('WARDEN_DOCKER_CHECK_SECRETS', true),
            'check_vulnerabilities' => env('WARDEN_DOCKER_CHECK_VULNERABILITIES', true),
            'severity_threshold' => env('WARDEN_DOCKER_SEVERITY_THRESHOLD', 'medium'),
            'timeout' => env('WARDEN_DOCKER_TIMEOUT', 600),
            'exclude_images' => env('WARDEN_DOCKER_EXCLUDE_IMAGES') ? explode(',', env('WARDEN_DOCKER_EXCLUDE_IMAGES')) : [],
            'custom_registry_urls' => env('WARDEN_DOCKER_CUSTOM_REGISTRY_URLS') ? explode(',', env('WARDEN_DOCKER_CUSTOM_REGISTRY_URLS')) : [],
        ],
        'kubernetes' => [
            'kubeconfig_path' => env('KUBECONFIG', '~/.kube/config'),
            'manifest_paths' => [
                'k8s/',
                'kubernetes/',
                'deploy/',
                'manifests/',
                '*.yaml',
                '*.yml',
            ],
            'scan_cluster' => env('WARDEN_KUBERNETES_SCAN_CLUSTER', true),
            'scan_manifests' => env('WARDEN_KUBERNETES_SCAN_MANIFESTS', true),
            'check_rbac' => env('WARDEN_KUBERNETES_CHECK_RBAC', true),
            'check_network_policies' => env('WARDEN_KUBERNETES_CHECK_NETWORK_POLICIES', true),
            'check_pod_security' => env('WARDEN_KUBERNETES_CHECK_POD_SECURITY', true),
            'check_secrets' => env('WARDEN_KUBERNETES_CHECK_SECRETS', true),
            'check_resource_limits' => env('WARDEN_KUBERNETES_CHECK_RESOURCE_LIMITS', true),
            'check_image_security' => env('WARDEN_KUBERNETES_CHECK_IMAGE_SECURITY', true),
            'check_service_accounts' => env('WARDEN_KUBERNETES_CHECK_SERVICE_ACCOUNTS', true),
            'check_admission_controllers' => env('WARDEN_KUBERNETES_CHECK_ADMISSION_CONTROLLERS', true),
            'severity_threshold' => env('WARDEN_KUBERNETES_SEVERITY_THRESHOLD', 'medium'),
            'timeout' => env('WARDEN_KUBERNETES_TIMEOUT', 300),
            'exclude_namespaces' => env('WARDEN_KUBERNETES_EXCLUDE_NAMESPACES') ? explode(',', env('WARDEN_KUBERNETES_EXCLUDE_NAMESPACES')) : ['kube-system', 'kube-public', 'kube-node-lease'],
            'exclude_workloads' => env('WARDEN_KUBERNETES_EXCLUDE_WORKLOADS') ? explode(',', env('WARDEN_KUBERNETES_EXCLUDE_WORKLOADS')) : [],
        ],
        'git' => [
            'repository_path' => env('WARDEN_GIT_REPOSITORY_PATH', base_path()),
            'scan_history' => env('WARDEN_GIT_SCAN_HISTORY', true),
            'scan_staged' => env('WARDEN_GIT_SCAN_STAGED', true),
            'scan_working_tree' => env('WARDEN_GIT_SCAN_WORKING_TREE', true),
            'max_commits' => env('WARDEN_GIT_MAX_COMMITS', 100),
            'check_secrets' => env('WARDEN_GIT_CHECK_SECRETS', true),
            'check_credentials' => env('WARDEN_GIT_CHECK_CREDENTIALS', true),
            'check_keys' => env('WARDEN_GIT_CHECK_KEYS', true),
            'check_tokens' => env('WARDEN_GIT_CHECK_TOKENS', true),
            'check_api_keys' => env('WARDEN_GIT_CHECK_API_KEYS', true),
            'check_certificates' => env('WARDEN_GIT_CHECK_CERTIFICATES', true),
            'check_passwords' => env('WARDEN_GIT_CHECK_PASSWORDS', true),
            'check_sensitive_files' => env('WARDEN_GIT_CHECK_SENSITIVE_FILES', true),
            'check_large_files' => env('WARDEN_GIT_CHECK_LARGE_FILES', true),
            'check_binary_files' => env('WARDEN_GIT_CHECK_BINARY_FILES', true),
            'max_file_size' => env('WARDEN_GIT_MAX_FILE_SIZE', 1048576),
            'severity_threshold' => env('WARDEN_GIT_SEVERITY_THRESHOLD', 'medium'),
            'timeout' => env('WARDEN_GIT_TIMEOUT', 300),
            'exclude_paths' => env('WARDEN_GIT_EXCLUDE_PATHS') ? explode(',', env('WARDEN_GIT_EXCLUDE_PATHS')) : [
                'vendor/', 'node_modules/', '.git/', 'storage/', 'bootstrap/cache/', 'tests/', '*.log', '*.tmp',
            ],
            'include_extensions' => env('WARDEN_GIT_INCLUDE_EXTENSIONS') ? explode(',', env('WARDEN_GIT_INCLUDE_EXTENSIONS')) : [
                'php', 'js', 'ts', 'jsx', 'tsx', 'vue', 'py', 'rb', 'java', 'go', 'rs', 'c', 'cpp', 'h',
                'yml', 'yaml', 'json', 'xml', 'ini', 'conf', 'config', 'env', 'sh', 'bash', 'zsh',
                'sql', 'md', 'txt', 'html', 'css', 'scss', 'less', 'dockerfile',
            ],
            'custom_patterns' => env('WARDEN_GIT_CUSTOM_PATTERNS') ? json_decode(env('WARDEN_GIT_CUSTOM_PATTERNS'), true) : [],
        ],
        'env' => [
            'sensitive_keys' => env('WARDEN_ENV_SENSITIVE_KEYS') ? explode(',', env('WARDEN_ENV_SENSITIVE_KEYS')) : [
                'DB_PASSWORD', 'API_KEY', 'SECRET_KEY', 'PRIVATE_KEY', 'MAIL_PASSWORD', 'REDIS_PASSWORD',
                'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'STRIPE_SECRET', 'PUBLISHABLE_KEY', 'JWT_SECRET',
                'ENCRYPTION_KEY', 'APP_KEY',
            ],
        ],
        'storage' => [
            'directories' => env('WARDEN_STORAGE_DIRECTORIES') ? explode(',', env('WARDEN_STORAGE_DIRECTORIES')) : [
                'storage/framework', 'storage/logs', 'bootstrap/cache',
            ],
            'check_permissions' => env('WARDEN_STORAGE_CHECK_PERMISSIONS', true),
            'check_existence' => env('WARDEN_STORAGE_CHECK_EXISTENCE', true),
            'required_permissions' => env('WARDEN_STORAGE_REQUIRED_PERMISSIONS', '755'),
        ],
        'debug' => [
            'dev_packages' => env('WARDEN_DEBUG_DEV_PACKAGES') ? explode(',', env('WARDEN_DEBUG_DEV_PACKAGES')) : [
                'barryvdh/laravel-debugbar', 'laravel/telescope', 'laravel/horizon', 'beyondcode/laravel-dump-server', 'laravel/dusk',
            ],
            'check_app_debug' => env('WARDEN_DEBUG_CHECK_APP_DEBUG', true),
            'check_dev_packages' => env('WARDEN_DEBUG_CHECK_DEV_PACKAGES', true),
            'check_telescope' => env('WARDEN_DEBUG_CHECK_TELESCOPE', true),
            'production_environments' => env('WARDEN_DEBUG_PRODUCTION_ENVIRONMENTS') ? explode(',', env('WARDEN_DEBUG_PRODUCTION_ENVIRONMENTS')) : ['production'],
        ],
        'security_patterns' => [
            'exclude_directories' => env('WARDEN_SECURITY_PATTERNS_EXCLUDE_DIRECTORIES') ? explode(',', env('WARDEN_SECURITY_PATTERNS_EXCLUDE_DIRECTORIES')) : [
                'vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git', 'tests',
            ],
            'exclude_files' => env('WARDEN_SECURITY_PATTERNS_EXCLUDE_FILES') ? explode(',', env('WARDEN_SECURITY_PATTERNS_EXCLUDE_FILES')) : [
                '*.min.php', 'vendor/*', 'node_modules/*',
            ],
            'included_extensions' => env('WARDEN_SECURITY_PATTERNS_INCLUDE_EXTENSIONS') ? explode(',', env('WARDEN_SECURITY_PATTERNS_INCLUDE_EXTENSIONS')) : ['.php'],
            'max_file_size' => env('WARDEN_SECURITY_PATTERNS_MAX_FILE_SIZE', 1048576),
            'timeout' => env('WARDEN_SECURITY_PATTERNS_TIMEOUT', 300),
            'severity_threshold' => env('WARDEN_SECURITY_PATTERNS_SEVERITY_THRESHOLD', 'medium'),
            'check_sql_injection' => env('WARDEN_SECURITY_PATTERNS_CHECK_SQL_INJECTION', true),
            'check_xss' => env('WARDEN_SECURITY_PATTERNS_CHECK_XSS', true),
            'check_file_inclusion' => env('WARDEN_SECURITY_PATTERNS_CHECK_FILE_INCLUSION', true),
            'check_code_execution' => env('WARDEN_SECURITY_PATTERNS_CHECK_CODE_EXECUTION', true),
            'check_hardcoded_secrets' => env('WARDEN_SECURITY_PATTERNS_CHECK_HARDCODED_SECRETS', true),
            'check_weak_crypto' => env('WARDEN_SECURITY_PATTERNS_CHECK_WEAK_CRYPTO', true),
            'check_debug_functions' => env('WARDEN_SECURITY_PATTERNS_CHECK_DEBUG_FUNCTIONS', true),
        ],
    ],
];