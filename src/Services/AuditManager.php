<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Data\AuditResult;
use Dgtlss\Warden\Data\AuditRunReport;

class AuditManager
{
    public function __construct(
        protected AuditRegistry $registry,
        protected AuditExecutor $executor,
        protected AuditCacheService $cacheService,
        protected FindingNormalizer $findingNormalizer,
        protected PolicyService $policyService,
        protected AuditHistoryService $historyService,
        protected CloudSyncService $cloudSyncService,
    ) {
    }

    /**
     * @param callable(string): void|null $onWarning
     * @param callable(string, string, ?float): void|null $onProgress
     */
    public function run(
        bool $includeJavascript = false,
        bool $force = false,
        ?string $profile = null,
        ?callable $onWarning = null,
        ?callable $onProgress = null,
    ): AuditRunReport {
        $profile = $this->resolveProfile($profile);
        $startedAt = microtime(true);
        $definitions = array_values(array_filter(
            $this->registry->definitions($includeJavascript, $onWarning),
            static fn (AuditDefinition $definition): bool => $definition->supportsProfile($profile)
        ));

        $results = [];
        $pending = [];
        $cacheEnabled = (bool) config('warden.cache.enabled', true);

        foreach ($definitions as $definition) {
            $signature = $this->signatureFor($definition, $profile);

            if ($cacheEnabled && !$force && $definition->cacheable && $this->cacheService->hasRecentAudit($definition->id, $signature)) {
                $cached = $this->cacheService->getCachedResult($definition->id, $signature);
                if ($cached !== null) {
                    $results[] = new AuditResult(
                        auditId: $definition->id,
                        auditName: $definition->name,
                        success: true,
                        findings: $this->findingNormalizer->normalize($cached['result'], $definition->name, $definition->id),
                        durationMs: 0.0,
                        cached: true,
                        metadata: isset($cached['metadata']) ? $cached['metadata'] : [],
                    );

                    continue;
                }
            }

            $pending[] = $definition;
        }

        $this->executor->reset();

        foreach ($pending as $definition) {
            $this->executor->addAudit($definition);
        }

        $rawResults = $this->executor->execute($profile, $onProgress);

        foreach ($rawResults as $rawResult) {
            $auditId = (string) $rawResult['audit_id'];
            $auditName = (string) $rawResult['audit_name'];
            $metadata = $rawResult['metadata'];

            $result = new AuditResult(
                auditId: $auditId,
                auditName: $auditName,
                success: (bool) $rawResult['success'],
                findings: $this->findingNormalizer->normalize((array) $rawResult['findings'], $auditName, $auditId),
                durationMs: (float) $rawResult['duration_ms'],
                cached: false,
                metadata: $metadata,
            );

            $results[] = $result;

            $definition = $this->registry->definition($auditId, $includeJavascript, $onWarning);
            if ($cacheEnabled && $definition !== null && $definition->cacheable) {
                $this->cacheService->storeResult(
                    auditName: $definition->id,
                    result: $result->findingsToArray(),
                    signature: $this->signatureFor($definition, $profile),
                    metadata: $metadata
                );
            }
        }

        usort($results, static fn (AuditResult $left, AuditResult $right): int => strcmp($left->auditId, $right->auditId));

        $allFindings = [];
        $abandonedPackages = [];
        $hasFailures = false;

        foreach ($results as $result) {
            if (!$result->success) {
                $hasFailures = true;
            }

            $allFindings = array_merge($allFindings, $result->findingsToArray());

            if (isset($result->metadata['abandoned_packages']) && is_array($result->metadata['abandoned_packages'])) {
                $abandonedPackages = array_merge($abandonedPackages, $result->metadata['abandoned_packages']);
            }
        }

        $suppression = $this->policyService->applySuppressions($allFindings);
        $report = new AuditRunReport(
            results: $results,
            findings: $suppression['active'],
            suppressedFindings: $suppression['suppressed'],
            abandonedPackages: $abandonedPackages,
            hasFailures: $hasFailures,
            durationMs: round((microtime(true) - $startedAt) * 1000, 1),
            profile: $profile,
            metadata: $this->buildContext(),
        );

        $this->historyService->store($report, $report->metadata);

        if ((bool) config('warden.cloud.auto_sync', false) && $this->cloudSyncService->isConfigured()) {
            $this->cloudSyncService->sync([
                'profile' => $report->profile,
                'duration_ms' => $report->durationMs,
                'has_failures' => $report->hasFailures,
                'findings' => $report->findings,
                'suppressed_findings' => $report->suppressedFindings,
                'metadata' => $report->metadata,
            ]);
        }

        return $report;
    }

    public function resolveProfile(?string $profile = null): string
    {
        $resolved = $profile ?? (string) config('warden.profile', 'legacy');
        $allowed = ['legacy', 'recommended', 'ci-strict', 'runtime-safe'];

        return in_array($resolved, $allowed, true) ? $resolved : 'legacy';
    }

    protected function signatureFor(AuditDefinition $definition, string $profile): string
    {
        $payload = [
            'version' => $this->wardenVersion(),
            'profile' => $profile,
            'config' => $this->configValues($definition->cacheConfig),
            'files' => [],
            'env' => [
                'app_env' => config('app.env'),
                'app_debug' => config('app.debug'),
            ],
        ];

        foreach ($definition->cachePaths as $pathPattern) {
            foreach (glob(base_path($pathPattern)) ?: [] as $path) {
                $payload['files'][str_replace(base_path() . DIRECTORY_SEPARATOR, '', $path)] = file_exists($path) && is_file($path)
                    ? hash_file('sha256', $path)
                    : (file_exists($path) ? 'dir:' . (string) @filemtime($path) : 'missing');
            }
        }

        return hash('sha256', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    /**
     * @param array<int, string> $keys
     * @return array<string, mixed>
     */
    protected function configValues(array $keys): array
    {
        $values = [];

        foreach ($keys as $key) {
            $values[$key] = config('warden.' . $key);
        }

        return $values;
    }

    /**
     * @return array<string, mixed>
     */
    protected function buildContext(): array
    {
        return [
            'trigger' => getenv('CI') !== false ? 'ci' : 'manual',
            'triggered_by' => getenv('GITHUB_ACTOR') ?: getenv('USER') ?: null,
            'branch' => getenv('GITHUB_REF_NAME') ?: getenv('CI_COMMIT_REF_NAME') ?: getenv('BRANCH_NAME') ?: null,
            'commit' => getenv('GITHUB_SHA') ?: getenv('CI_COMMIT_SHA') ?: getenv('GIT_COMMIT') ?: null,
            'build_id' => getenv('GITHUB_RUN_ID') ?: getenv('CI_PIPELINE_ID') ?: getenv('BUILD_ID') ?: null,
            'ci_provider' => $this->detectCiProvider(),
        ];
    }

    protected function detectCiProvider(): ?string
    {
        if (getenv('GITHUB_ACTIONS') !== false) {
            return 'github-actions';
        }

        if (getenv('GITLAB_CI') !== false) {
            return 'gitlab-ci';
        }

        if (getenv('JENKINS_URL') !== false) {
            return 'jenkins';
        }

        if (getenv('CI') !== false) {
            return 'generic-ci';
        }

        return null;
    }

    protected function wardenVersion(): string
    {
        $composerPath = dirname(__DIR__, 2) . '/composer.json';

        $contents = file_get_contents($composerPath);
        $decoded = $contents !== false ? json_decode($contents, true) : null;

        return is_array($decoded) && isset($decoded['version']) && is_string($decoded['version'])
            ? $decoded['version']
            : 'unknown';
    }
}
