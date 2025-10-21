<?php

namespace Dgtlss\Warden\Plugins;

use Dgtlss\Warden\Abstracts\AbstractAuditPlugin;
use Dgtlss\Warden\Services\Dependencies\DependencyResolver;
use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Services\Audits\EnvAuditService;
use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use Dgtlss\Warden\Services\Audits\ConfigAuditService;
use Dgtlss\Warden\Services\Audits\PhpSyntaxAuditService;
use Dgtlss\Warden\Services\Audits\DockerAuditService;

class CoreAuditPlugin extends AbstractAuditPlugin
{
    protected DependencyResolver $dependencyResolver;

    public function __construct(DependencyResolver $dependencyResolver)
    {
        $this->dependencyResolver = $dependencyResolver;
    }

    /**
     * Get the human-readable name of this plugin.
     *
     * @return string
     */
    public function getName(): string
    {
        return 'Core Audit Plugin';
    }

    /**
     * Get the description of what this plugin does.
     *
     * @return string
     */
    public function getDescription(): string
    {
        return 'Provides core security audits for Laravel applications including Composer, NPM, Environment, and Configuration audits.';
    }

    /**
     * Get the version of this plugin.
     *
     * @return string
     */
    public function getVersion(): string
    {
        return '2.0.0';
    }

    /**
     * Get the author of this plugin.
     *
     * @return string
     */
    public function getAuthor(): string
    {
        return 'Nathan Langer';
    }

    /**
     * Get the dependencies required by this plugin.
     *
     * @return array
     */
    public function getDependencies(): array
    {
        return [];
    }

    /**
     * Get the audit classes provided by this plugin.
     *
     * @return array
     */
    public function getAuditClasses(): array
    {
        return [
            ComposerAuditService::class,
            NpmAuditService::class,
            EnvAuditService::class,
            StorageAuditService::class,
            DebugModeAuditService::class,
            ConfigAuditService::class,
            PhpSyntaxAuditService::class,
            DockerAuditService::class,
        ];
    }

    /**
     * Check if this plugin is compatible with the current environment.
     *
     * @return bool
     */
    public function isCompatible(): bool
    {
        // Check for basic Laravel environment
        if (!function_exists('base_path')) {
            $this->error('Laravel framework not detected');
            return false;
        }

        // Check for required PHP extensions
        $requiredExtensions = ['json', 'mbstring'];
        foreach ($requiredExtensions as $extension) {
            if (!$this->checkExtension($extension)) {
                $this->error("Required PHP extension '{$extension}' is not available");
                return false;
            }
        }

        return true;
    }

    /**
     * Get the default configuration for this plugin.
     *
     * @return array
     */
    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'audits' => [
                'composer' => [
                    'enabled' => true,
                    'timeout' => 300,
                    'ignore_abandoned' => false,
                ],
                'npm' => [
                    'enabled' => true,
                    'timeout' => 300,
                    'auto_include' => false, // Only run if --npm flag is used
                ],
                'env' => [
                    'enabled' => true,
                    'check_gitignore' => true,
                    'sensitive_keys' => [],
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
                    'enabled' => false,
                    'exclude' => [
                        'vendor',
                        'node_modules',
                        'storage',
                        'bootstrap/cache',
                        '.git',
                    ],
                ],
                'docker' => [
                    'enabled' => true,
                    'timeout' => 600,
                    'dockerfile_path' => 'Dockerfile',
                    'docker_compose_path' => 'docker-compose.yml',
                    'scan_images' => true,
                    'scan_dockerfile' => true,
                    'scan_docker_compose' => true,
                    'check_base_images' => true,
                    'check_secrets' => true,
                    'check_vulnerabilities' => true,
                    'severity_threshold' => 'medium',
                    'exclude_images' => [],
                    'custom_registry_urls' => [],
                ],
            ]
        ]);
    }

    /**
     * Initialize the plugin.
     *
     * @param array $config
     * @return void
     */
    public function initialize(array $config = []): void
    {
        parent::initialize($config);

        // Register plugin-specific dependencies
        $this->registerDependencies();

        $this->info('Core audit plugin initialized successfully');
    }

    /**
     * Register plugin dependencies.
     *
     * @return void
     */
    protected function registerDependencies(): void
    {
        // Composer dependency
        if ($this->getConfig('audits.composer.enabled', true)) {
            $composerDep = $this->dependencyResolver->createSystemCommandDependency(
                'composer',
                ['--version'],
                'curl -sS https://getcomposer.org/installer | php'
            );
            $this->dependencyResolver->addDependency($composerDep);
        }

        // NPM dependency
        if ($this->getConfig('audits.npm.enabled', true)) {
            $npmDep = $this->dependencyResolver->createSystemCommandDependency(
                'npm',
                ['--version'],
                'npm install -g npm'
            );
            $this->dependencyResolver->addDependency($npmDep);
        }

        // File dependencies for storage audit
        if ($this->getConfig('audits.storage.enabled', true)) {
            $requiredDirs = $this->getConfig('audits.storage.required_directories', ['storage', 'bootstrap/cache']);
            foreach ($requiredDirs as $dir) {
                $fileDep = $this->dependencyResolver->createFileDependency($dir, true, true);
                $this->dependencyResolver->addDependency($fileDep);
            }
        }

        // .env file dependency for environment audit
        if ($this->getConfig('audits.env.enabled', true)) {
            $envDep = $this->dependencyResolver->createFileDependency('.env', true, false);
            $this->dependencyResolver->addDependency($envDep);
        }

        // Docker dependency for Docker audit
        if ($this->getConfig('audits.docker.enabled', true)) {
            $dockerDep = $this->dependencyResolver->createSystemCommandDependency(
                'docker',
                ['--version'],
                null // No auto-install for Docker
            );
            $this->dependencyResolver->addDependency($dockerDep);
        }
    }

    /**
     * Get the configuration schema for this plugin.
     *
     * @return array
     */
    public function getConfigSchema(): array
    {
        return array_merge(parent::getConfigSchema(), [
            'audits' => [
                'type' => 'object',
                'description' => 'Configuration for individual audits',
                'properties' => [
                    'composer' => [
                        'type' => 'object',
                        'properties' => [
                            'enabled' => ['type' => 'boolean', 'default' => true],
                            'timeout' => ['type' => 'integer', 'default' => 300],
                            'ignore_abandoned' => ['type' => 'boolean', 'default' => false],
                        ]
                    ],
                    'npm' => [
                        'type' => 'object',
                        'properties' => [
                            'enabled' => ['type' => 'boolean', 'default' => true],
                            'timeout' => ['type' => 'integer', 'default' => 300],
                            'auto_include' => ['type' => 'boolean', 'default' => false],
                        ]
                    ],
                    'env' => [
                        'type' => 'object',
                        'properties' => [
                            'enabled' => ['type' => 'boolean', 'default' => true],
                            'check_gitignore' => ['type' => 'boolean', 'default' => true],
                            'sensitive_keys' => ['type' => 'array', 'default' => []],
                        ]
                    ],
                    'storage' => [
                        'type' => 'object',
                        'properties' => [
                            'enabled' => ['type' => 'boolean', 'default' => true],
                            'check_permissions' => ['type' => 'boolean', 'default' => true],
                            'required_directories' => ['type' => 'array', 'default' => ['storage', 'bootstrap/cache']],
                        ]
                    ],
                    'debug' => [
                        'type' => 'object',
                        'properties' => [
                            'enabled' => ['type' => 'boolean', 'default' => true],
                            'check_debug_mode' => ['type' => 'boolean', 'default' => true],
                            'check_env_debug' => ['type' => 'boolean', 'default' => true],
                        ]
                    ],
                    'config' => [
                        'type' => 'object',
                        'properties' => [
                            'enabled' => ['type' => 'boolean', 'default' => true],
                            'check_session_security' => ['type' => 'boolean', 'default' => true],
                            'check_csrf_protection' => ['type' => 'boolean', 'default' => true],
                        ]
                    ],
                    'php_syntax' => [
                        'type' => 'object',
                        'properties' => [
                            'enabled' => ['type' => 'boolean', 'default' => false],
                            'exclude' => ['type' => 'array', 'default' => ['vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git']],
                        ]
                    ],
                    'docker' => [
                        'type' => 'object',
                        'properties' => [
                            'enabled' => ['type' => 'boolean', 'default' => true],
                            'timeout' => ['type' => 'integer', 'default' => 600],
                            'dockerfile_path' => ['type' => 'string', 'default' => 'Dockerfile'],
                            'docker_compose_path' => ['type' => 'string', 'default' => 'docker-compose.yml'],
                            'scan_images' => ['type' => 'boolean', 'default' => true],
                            'scan_dockerfile' => ['type' => 'boolean', 'default' => true],
                            'scan_docker_compose' => ['type' => 'boolean', 'default' => true],
                            'check_base_images' => ['type' => 'boolean', 'default' => true],
                            'check_secrets' => ['type' => 'boolean', 'default' => true],
                            'check_vulnerabilities' => ['type' => 'boolean', 'default' => true],
                            'severity_threshold' => ['type' => 'string', 'default' => 'medium', 'enum' => ['low', 'medium', 'high', 'critical']],
                            'exclude_images' => ['type' => 'array', 'default' => []],
                            'custom_registry_urls' => ['type' => 'array', 'default' => []],
                        ]
                    ],
                ]
            ]
        ]);
    }
}