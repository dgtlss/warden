<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\CustomAudit;
use Dgtlss\Warden\Services\Audits\CiWorkflowAuditService;
use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use Dgtlss\Warden\Services\Audits\DockerSecurityAuditService;
use Dgtlss\Warden\Services\Audits\EnvAuditService;
use Dgtlss\Warden\Services\Audits\LaravelPostureAuditService;
use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Services\Audits\RepositorySecretsAuditService;
use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Illuminate\Support\Str;

class AuditRegistry
{
    /**
     * @return array<int, AuditDefinition>
     */
    public function definitions(bool $includeJavascript = false, ?callable $onWarning = null): array
    {
        $definitions = [
            new AuditDefinition(
                id: 'composer',
                name: 'composer',
                factory: fn () => app(ComposerAuditService::class),
                profiles: ['legacy', 'recommended', 'ci-strict', 'runtime-safe'],
                cachePaths: ['composer.json', 'composer.lock'],
                cacheConfig: ['policy.composer', 'profile']
            ),
            new AuditDefinition(
                id: 'environment',
                name: 'environment',
                factory: fn () => app(EnvAuditService::class),
                profiles: ['legacy', 'recommended', 'ci-strict', 'runtime-safe'],
                cachePaths: ['.env', '.gitignore'],
                cacheConfig: ['sensitive_keys', 'profile'],
                cacheable: false
            ),
            new AuditDefinition(
                id: 'storage',
                name: 'storage',
                factory: fn () => app(StorageAuditService::class),
                profiles: ['legacy', 'recommended', 'ci-strict', 'runtime-safe'],
                cachePaths: ['storage/framework', 'storage/logs', 'bootstrap/cache'],
                cacheConfig: ['profile'],
                cacheable: false
            ),
            new AuditDefinition(
                id: 'debug-mode',
                name: 'debug-mode',
                factory: fn () => app(DebugModeAuditService::class),
                profiles: ['legacy', 'recommended', 'ci-strict', 'runtime-safe'],
                cachePaths: ['vendor/composer/installed.json', 'config/app.php'],
                cacheConfig: ['profile'],
                cacheable: false
            ),
            new AuditDefinition(
                id: 'laravel-posture',
                name: 'laravel-posture',
                factory: fn () => app(LaravelPostureAuditService::class),
                profiles: ['recommended', 'ci-strict', 'runtime-safe'],
                cachePaths: ['config/app.php', 'config/session.php', 'config/cors.php', 'public/storage'],
                cacheConfig: ['profile'],
                cacheable: false
            ),
            new AuditDefinition(
                id: 'repository-secrets',
                name: 'repository-secrets',
                factory: fn () => app(RepositorySecretsAuditService::class),
                profiles: ['recommended', 'ci-strict'],
                cachePaths: [
                    '.env.example',
                    'config/*.php',
                    'docker-compose.yml',
                    'docker-compose.yaml',
                    '.github/workflows/*.yml',
                    '.github/workflows/*.yaml',
                ],
                cacheConfig: ['profile']
            ),
            new AuditDefinition(
                id: 'ci-workflow',
                name: 'ci-workflow',
                factory: fn () => app(CiWorkflowAuditService::class),
                profiles: ['recommended', 'ci-strict'],
                cachePaths: ['.github/workflows/*.yml', '.github/workflows/*.yaml'],
                cacheConfig: ['profile']
            ),
            new AuditDefinition(
                id: 'docker-security',
                name: 'docker-security',
                factory: fn () => app(DockerSecurityAuditService::class),
                profiles: ['recommended', 'ci-strict'],
                cachePaths: ['Dockerfile', 'Dockerfile.*', 'docker-compose.yml', 'docker-compose.yaml'],
                cacheConfig: ['profile']
            ),
        ];

        if ($includeJavascript) {
            $definitions[] = new AuditDefinition(
                id: 'npm',
                name: 'npm',
                factory: fn () => app(NpmAuditService::class),
                profiles: ['legacy', 'recommended', 'ci-strict', 'runtime-safe'],
                cachePaths: ['package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'],
                cacheConfig: ['profile']
            );
        }

        foreach ((array) config('warden.custom_audits', []) as $customAuditClass) {
            if (!is_string($customAuditClass) || !class_exists($customAuditClass)) {
                if ($onWarning !== null) {
                    $onWarning('Custom audit class not found: ' . (string) $customAuditClass);
                }

                continue;
            }

            try {
                $audit = app()->make($customAuditClass);
            } catch (\Throwable $exception) {
                if ($onWarning !== null) {
                    $onWarning(sprintf('Failed to load custom audit %s: %s', $customAuditClass, $exception->getMessage()));
                }

                continue;
            }

            if (!$audit instanceof CustomAudit) {
                if ($onWarning !== null) {
                    $onWarning(sprintf('Custom audit %s must implement %s', $customAuditClass, CustomAudit::class));
                }

                continue;
            }

            if (!$audit->shouldRun()) {
                continue;
            }

            $definitions[] = new AuditDefinition(
                id: 'custom-' . Str::slug($audit->getName() ?: class_basename($customAuditClass)),
                name: $audit->getName(),
                factory: fn () => new CustomAuditWrapper(app()->make($customAuditClass)),
                profiles: ['legacy', 'recommended', 'ci-strict', 'runtime-safe'],
                cachePaths: [],
                cacheConfig: ['custom_audits'],
                cacheable: false
            );
        }

        return $definitions;
    }

    public function definition(string $id, bool $includeJavascript = true, ?callable $onWarning = null): ?AuditDefinition
    {
        foreach ($this->definitions($includeJavascript, $onWarning) as $definition) {
            if ($definition->id === $id) {
                return $definition;
            }
        }

        return null;
    }
}
