<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Contracts\CustomAudit;
use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\LaravelConfigAuditService;
use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Services\Audits\PlatformAuditService;
use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Dgtlss\Warden\Services\Audits\SupplyChainAuditService;
use Dgtlss\Warden\Services\Audits\SourceAuditService;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Illuminate\Contracts\Container\Container;
use Throwable;

class AuditRunner
{
    public function __construct(
        private readonly Container $container,
        private readonly AuditExecutor $auditExecutor,
        private readonly RulePolicy $rulePolicy,
    ) {
    }

    /**
     * @param callable(string, string, ?float): void|null $onProgress
     */
    public function run(AuditContext $auditContext, ?callable $onProgress = null): AuditReport
    {
        $policyErrors = $this->rulePolicy->errors();
        if ($policyErrors !== []) {
            return new AuditReport($auditContext, [], configurationErrors: $policyErrors, scannedAt: $auditContext->scanTime());
        }

        [$services, $errors] = $this->services($auditContext);
        if ($errors !== []) {
            return new AuditReport($auditContext, [], configurationErrors: $errors, scannedAt: $auditContext->scanTime());
        }

        $results = $this->rulePolicy->apply($this->auditExecutor->execute($auditContext, $services, $onProgress));

        return new AuditReport($auditContext, $results, configurationErrors: $errors, scannedAt: $auditContext->scanTime());
    }

    /** @return list<string> */
    public function availableAuditIds(): array
    {
        $ids = ['supply-chain', 'composer', 'npm', 'laravel-config', 'platform', 'source', 'storage'];
        $customAudits = config('warden.custom_audits', []);
        if (is_array($customAudits)) {
            foreach ($customAudits as $customAudit) {
                if (!is_string($customAudit) || !class_exists($customAudit)) {
                    continue;
                }

                try {
                    $audit = $this->container->make($customAudit);
                    if ($audit instanceof CustomAudit) {
                        $ids[] = $audit->getName();
                    }
                } catch (Throwable) {
                    // Invalid custom audits are represented as report errors when a run starts.
                }
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * @return array{0: list<AuditServiceInterface>, 1: list<AuditError>}
     */
    private function services(AuditContext $auditContext): array
    {
        $services = [];
        $errors = [];
        $builtInClasses = [
            SupplyChainAuditService::class,
            ComposerAuditService::class,
            NpmAuditService::class,
            LaravelConfigAuditService::class,
            PlatformAuditService::class,
            SourceAuditService::class,
            StorageAuditService::class,
        ];
        foreach ($builtInClasses as $class) {
            try {
                $services[] = $this->container->make($class);
            } catch (Throwable $throwable) {
                $errors[] = new AuditError(
                    'configuration',
                    'builtin_audit_initialization_failed',
                    sprintf('%s: %s', $class, $throwable->getMessage()),
                );
            }
        }

        $customAudits = config('warden.custom_audits', []);
        if (!is_array($customAudits)) {
            $errors[] = new AuditError('configuration', 'invalid_custom_audits', 'warden.custom_audits must be an array.');
            $customAudits = [];
        }

        foreach ($customAudits as $class) {
            if (!is_string($class) || !class_exists($class)) {
                $errors[] = new AuditError('configuration', 'custom_audit_not_found', sprintf('Custom audit class %s was not found.', is_scalar($class) ? (string) $class : 'unknown'));
                continue;
            }

            try {
                $customAudit = $this->container->make($class);
                if (!$customAudit instanceof CustomAudit) {
                    $errors[] = new AuditError('configuration', 'invalid_custom_audit', sprintf('%s must implement %s.', $class, CustomAudit::class));
                    continue;
                }

                $customName = $customAudit->getName();
                if (in_array($customName, array_map(static fn (AuditServiceInterface $auditService): string => $auditService->getName(), $services), true)) {
                    $errors[] = new AuditError('configuration', 'duplicate_audit_id', sprintf('Audit ID "%s" is already registered.', $customName));
                    continue;
                }

                if ($customAudit->shouldRun($auditContext)) {
                    $services[] = new CustomAuditWrapper($customAudit);
                }
            } catch (Throwable $throwable) {
                $errors[] = new AuditError('configuration', 'custom_audit_initialization_failed', sprintf('%s: %s', $class, $throwable->getMessage()));
            }
        }

        $available = array_map(static fn (AuditServiceInterface $auditService): string => $auditService->getName(), $services);
        foreach ([...$auditContext->only, ...$auditContext->skip] as $requested) {
            if (!in_array($requested, $available, true)) {
                $errors[] = new AuditError('configuration', 'unknown_audit', sprintf('Unknown audit "%s".', $requested));
            }
        }

        $selected = array_values(array_filter(
            $services,
            static fn (AuditServiceInterface $auditService): bool => $auditContext->includes($auditService->getName()),
        ));

        return [$selected, $errors];
    }
}
