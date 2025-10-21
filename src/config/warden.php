<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Warden Security Audit Configuration
    |--------------------------------------------------------------------------
    */

    /*
    |--------------------------------------------------------------------------
    | Notification Settings
    |--------------------------------------------------------------------------
    |
    | Configure where Warden should send security audit notifications.
    | Multiple notification channels are supported. Configure them here
    | or use environment variables for sensitive data like webhook URLs.
    |
    */

    // Legacy support - maintained for backward compatibility
    'webhook_url' => env('WARDEN_WEBHOOK_URL', null),
    'email_recipients' => env('WARDEN_EMAIL_RECIPIENTS', null),

    'notifications' => [
        'enabled' => env('WARDEN_NOTIFICATIONS_ENABLED', true),
        
        'channels' => ['slack', 'email'], // Default enabled channels
        
        'slack' => [
            'enabled' => true,
            'webhook_url' => env('WARDEN_SLACK_WEBHOOK_URL'), // Keep ENV for security
            'channel' => env('WARDEN_SLACK_CHANNEL', '#security'),
            'username' => env('WARDEN_SLACK_USERNAME', 'Warden'),
            'icon_emoji' => ':shield:',
        ],
        
        'discord' => [
            'enabled' => false, // Disabled by default
            'webhook_url' => env('WARDEN_DISCORD_WEBHOOK_URL'), // Keep ENV for security
            'username' => env('WARDEN_DISCORD_USERNAME', 'Warden'),
        ],
        
        'teams' => [
            'enabled' => false, // Disabled by default
            'webhook_url' => env('WARDEN_TEAMS_WEBHOOK_URL'), // Keep ENV for security
            'title' => 'Warden Security Audit',
        ],
        
        'email' => [
            'enabled' => true,
            'recipients' => env('WARDEN_EMAIL_RECIPIENTS', null), // Keep ENV for security
            'from_address' => env('WARDEN_EMAIL_FROM', config('mail.from.address')),
            'from_name' => env('WARDEN_EMAIL_FROM_NAME', 'Warden Security'),
            'template' => 'warden::mail.report',
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
        'duration' => env('WARDEN_CACHE_DURATION', 3600), // 1 hour in seconds
        'driver' => env('WARDEN_CACHE_DRIVER', config('cache.default')),
        'prefix' => 'warden_audit',
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
        'retry_attempts' => env('WARDEN_RETRY_ATTEMPTS', 3),
        'retry_delay' => env('WARDEN_RETRY_DELAY', 1000), // milliseconds
        'severity_filter' => env('WARDEN_SEVERITY_FILTER', null), // null|low|medium|high|critical

        // Individual audit configurations
        'composer' => [
            'enabled' => true,
            'timeout' => 300,
            'ignore_abandoned' => false,
            'format' => 'json',
        ],
        
        'npm' => [
            'enabled' => true,
            'timeout' => 300,
            'auto_include' => false, // Only run with --npm flag
            'require_lockfile' => true,
        ],
        
        'env' => [
            'enabled' => true,
            'check_gitignore' => true,
            'sensitive_keys' => [
                'DB_PASSWORD',
                'API_KEY',
                'SECRET_KEY',
                'PRIVATE_KEY',
            ],
        ],
        
        'storage' => [
            'enabled' => true,
            'check_permissions' => true,
            'required_directories' => ['storage', 'bootstrap/cache'],
        ],
        
        'debug' => [
            'enabled' => true,
            'check_debug_mode' => true,
            'check_env_debug' => true,
        ],
        
        'config' => [
            'enabled' => true,
            'check_session_security' => true,
            'check_csrf_protection' => true,
        ],
        
        'php_syntax' => [
            'enabled' => env('WARDEN_PHP_SYNTAX_AUDIT_ENABLED', false), // Disabled by default as it can be slow
            'exclude' => [
                'vendor',
                'node_modules',
                'storage',
                'bootstrap/cache',
                '.git',
            ],
        ],
        
        'docker' => [
            'enabled' => env('WARDEN_DOCKER_AUDIT_ENABLED', true),
            'timeout' => 600, // 10 minutes for Docker scans
            'dockerfile_path' => env('WARDEN_DOCKERFILE_PATH', 'Dockerfile'),
            'docker_compose_path' => env('WARDEN_DOCKER_COMPOSE_PATH', 'docker-compose.yml'),
            'scan_images' => env('WARDEN_DOCKER_SCAN_IMAGES', true),
            'scan_dockerfile' => env('WARDEN_DOCKER_SCAN_DOCKERFILE', true),
            'scan_docker_compose' => env('WARDEN_DOCKER_SCAN_DOCKER_COMPOSE', true),
            'check_base_images' => env('WARDEN_DOCKER_CHECK_BASE_IMAGES', true),
            'check_secrets' => env('WARDEN_DOCKER_CHECK_SECRETS', true),
            'check_vulnerabilities' => env('WARDEN_DOCKER_CHECK_VULNERABILITIES', true),
            'severity_threshold' => env('WARDEN_DOCKER_SEVERITY_THRESHOLD', 'medium'), // low|medium|high|critical
            'exclude_images' => env('WARDEN_DOCKER_EXCLUDE_IMAGES', ''),
            'custom_registry_urls' => env('WARDEN_DOCKER_CUSTOM_REGISTRY_URLS', ''),
        ],
        
        'kubernetes' => [
            'enabled' => env('WARDEN_KUBERNETES_AUDIT_ENABLED', true),
            'timeout' => 300, // 5 minutes for kubectl operations
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
            'severity_threshold' => env('WARDEN_KUBERNETES_SEVERITY_THRESHOLD', 'medium'), // low|medium|high|critical
            'exclude_namespaces' => env('WARDEN_KUBERNETES_EXCLUDE_NAMESPACES', 'kube-system,kube-public,kube-node-lease'),
            'exclude_workloads' => env('WARDEN_KUBERNETES_EXCLUDE_WORKLOADS', ''),
        ],
        
        'git' => [
            'enabled' => env('WARDEN_GIT_AUDIT_ENABLED', true),
            'timeout' => 300, // 5 minutes for git operations
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
            'max_file_size' => env('WARDEN_GIT_MAX_FILE_SIZE', 1048576), // 1MB
            'severity_threshold' => env('WARDEN_GIT_SEVERITY_THRESHOLD', 'medium'), // low|medium|high|critical
            'exclude_paths' => env('WARDEN_GIT_EXCLUDE_PATHS', 'vendor/,node_modules/,/.git/,storage/,bootstrap/cache/,tests/,*.log,*.tmp'),
            'include_extensions' => env('WARDEN_GIT_INCLUDE_EXTENSIONS', 'php,js,ts,jsx,tsx,vue,py,rb,java,go,rs,c,cpp,h,yml,yaml,json,xml,ini,conf,config,env,sh,bash,zsh,sql,md,txt,html,css,scss,less,dockerfile'),
            'custom_patterns' => env('WARDEN_GIT_CUSTOM_PATTERNS', ''),
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
        'enabled' => env('WARDEN_SCHEDULE_ENABLED', false), // Disabled by default
        'frequency' => env('WARDEN_SCHEDULE_FREQUENCY', 'daily'), // hourly|daily|weekly|monthly
        'time' => env('WARDEN_SCHEDULE_TIME', '03:00'), // Time in 24h format
        'timezone' => env('WARDEN_SCHEDULE_TIMEZONE', config('app.timezone')),
        'silent' => true, // Run silently when scheduled
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
        'enabled' => env('WARDEN_HISTORY_ENABLED', false), // Disabled by default
        'table' => env('WARDEN_HISTORY_TABLE', 'warden_audit_history'),
        'retention_days' => env('WARDEN_HISTORY_RETENTION_DAYS', 90),
        'cleanup_frequency' => 'weekly', // How often to clean old records
    ],

    /*
    |--------------------------------------------------------------------------
    | Output Configuration
    |--------------------------------------------------------------------------
    |
    | Configure default output formats and behavior.
    |
    */

    'output' => [
        'default_format' => 'console', // console|json|junit|markdown|github|gitlab|jenkins
        'show_summary' => true,
        'show_details' => true,
        'group_by_severity' => true,
        
        'formats' => [
            'json' => [
                'pretty_print' => true,
                'include_metadata' => true,
            ],
            'junit' => [
                'test_name' => 'WardenSecurityAudit',
                'classname' => 'Warden',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Plugin System Configuration
    |--------------------------------------------------------------------------
    |
    | Configure the plugin system for extensible audit functionality.
    | This allows you to add custom audit plugins and manage their behavior.
    |
    */

    'plugins' => [
        'enabled' => true,
        'auto_discover' => env('WARDEN_PLUGINS_AUTO_DISCOVER', true),

        'discovery_paths' => [
            base_path('app/Warden/Plugins'),
            base_path('plugins'),
            __DIR__ . '/../Plugins',
        ],

        'register' => [
            // \App\Warden\Plugins\MyCustomPlugin::class,
        ],

        'config' => [
            'core-audit' => [
                'enabled' => true,
                'audits' => [
                    'composer' => ['enabled' => true],
                    'npm' => ['enabled' => true],
                    'env' => ['enabled' => true],
                    'storage' => ['enabled' => true],
                    'debug' => ['enabled' => true],
                    'config' => ['enabled' => true],
                    'php_syntax' => ['enabled' => false],
                    'docker' => ['enabled' => true],
                    'kubernetes' => ['enabled' => true],
                    'git' => ['enabled' => true],
                ],
            ],
        ],

        'dependencies' => [
            'auto_resolve' => env('WARDEN_PLUGINS_AUTO_RESOLVE_DEPS', true),
            'fail_on_unresolved' => env('WARDEN_PLUGINS_FAIL_ON_UNRESOLVED_DEPS', false),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Performance Configuration
    |--------------------------------------------------------------------------
    |
    | Configure performance-related settings for audit execution.
    |
    */

    'performance' => [
        'max_concurrent_audits' => 5,
        'memory_limit' => '512M',
        'time_limit' => 600, // 10 minutes
        'chunk_size' => 100, // For processing large datasets
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Configuration
    |--------------------------------------------------------------------------
    |
    | Define security-related settings and sensitive keys to check.
    |
    */

    'security' => [
        // Environment variables that should be checked during security audits
        'sensitive_keys' => [
            // 'DB_PASSWORD',
            // 'API_KEY',
            // 'SECRET_KEY',
            // 'PRIVATE_KEY',
            // 'ENCRYPTION_KEY',
            // 'JWT_SECRET',
            // 'STRIPE_SECRET',
            // 'AWS_SECRET_ACCESS_KEY',
            // 'GOOGLE_CLOUD_KEY',
        ],
        
        // Additional security checks
        'check_default_passwords' => true,
        'check_weak_configurations' => true,
        'check_exposed_secrets' => true,
    ],

    
];
