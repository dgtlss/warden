<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Data\AuditRunReport;
use Dgtlss\Warden\Data\ResolutionPlan;
use Dgtlss\Warden\Data\ResolutionPlanItem;

class ResolutionPlanner
{
    public function __construct(protected ResolverRegistry $registry)
    {
    }

    /**
     * @param array<string, mixed> $options
     */
    public function buildPlan(AuditRunReport $report, array $options = []): ResolutionPlan
    {
        $items = [];

        foreach ($report->findings as $finding) {
            if (!(bool) ($finding['resolvable'] ?? false)) {
                continue;
            }

            if (!$this->matchesFilters($finding, $options)) {
                continue;
            }

            $item = $this->registry->planForFinding($finding, $options);
            if ($item === null) {
                continue;
            }

            $items[] = $item;
        }

        foreach ($report->abandonedPackages as $abandonedPackage) {
            $finding = $this->abandonedPackageFinding($abandonedPackage);
            if (!$this->matchesFilters($finding, $options)) {
                continue;
            }

            $item = $this->registry->planForFinding($finding, $options);
            if ($item === null) {
                continue;
            }

            $items[] = $item;
        }

        return new ResolutionPlan(
            items: $this->deduplicate($items),
            filters: [
                'source' => $options['source'] ?? null,
                'package' => $options['package'] ?? null,
                'rule' => $options['rule'] ?? null,
            ],
        );
    }

    /**
     * @param array<string, mixed> $finding
     * @param array<string, mixed> $options
     */
    protected function matchesFilters(array $finding, array $options): bool
    {
        if (isset($options['source']) && is_string($options['source']) && $options['source'] !== '') {
            $source = (string) ($finding['source'] ?? ($finding['resolver_type'] ?? ''));
            $resolverType = (string) ($finding['resolver_type'] ?? '');

            if ($options['source'] === 'composer' && !in_array($source, ['composer'], true) && $resolverType !== 'composer') {
                return false;
            }

            if ($options['source'] === 'npm' && !in_array($source, ['npm'], true) && $resolverType !== 'javascript') {
                return false;
            }
        }

        if (isset($options['package']) && is_string($options['package']) && $options['package'] !== '') {
            if (($finding['package'] ?? null) !== $options['package']) {
                return false;
            }
        }

        if (isset($options['rule']) && is_string($options['rule']) && $options['rule'] !== '') {
            if (($finding['rule_id'] ?? null) !== $options['rule']) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<int, ResolutionPlanItem> $items
     * @return array<int, ResolutionPlanItem>
     */
    protected function deduplicate(array $items): array
    {
        $grouped = [];

        foreach ($items as $item) {
            $key = implode('|', [
                $item->source,
                $item->package,
                $item->strategy,
                implode('||', $item->displayCommands()),
                $item->reason ?? '',
            ]);

            if (!isset($grouped[$key])) {
                $grouped[$key] = $item;
                continue;
            }

            $existing = $grouped[$key];
            $mergedRuleIds = array_values(array_unique(array_merge($existing->ruleIds, $item->ruleIds)));
            $mergedMetadata = array_merge($existing->metadata, $item->metadata);

            $grouped[$key] = new ResolutionPlanItem(
                id: $existing->id,
                source: $existing->source,
                package: $existing->package,
                title: $existing->title,
                ruleIds: $mergedRuleIds,
                commands: $existing->commands,
                expectedFiles: $existing->expectedFiles,
                riskLevel: $existing->riskLevel,
                requiresNetwork: $existing->requiresNetwork,
                verificationSteps: $existing->verificationSteps,
                strategy: $existing->strategy,
                actionable: $existing->actionable,
                reason: $existing->reason,
                metadata: $mergedMetadata,
            );
        }

        return array_values($grouped);
    }

    /**
     * @param array<string, mixed> $abandonedPackage
     * @return array<string, mixed>
     */
    protected function abandonedPackageFinding(array $abandonedPackage): array
    {
        return [
            'source' => 'composer',
            'package' => $abandonedPackage['package'] ?? 'composer',
            'title' => 'Abandoned package detected',
            'rule_id' => sprintf('composer.abandoned.%s', str_replace('/', '.', (string) ($abandonedPackage['package'] ?? 'package'))),
            'category' => 'dependency',
            'severity' => 'medium',
            'description' => 'Composer reported this package as abandoned.',
            'resolver_type' => 'composer',
            'resolution_strategy' => 'abandoned-replace',
            'replacement' => $abandonedPackage['replacement'] ?? null,
            'is_direct_dependency' => $abandonedPackage['is_direct_dependency'] ?? false,
            'is_dev_dependency' => $abandonedPackage['is_dev_dependency'] ?? false,
            'declared_constraint' => $abandonedPackage['declared_constraint'] ?? null,
            'installed_version' => $abandonedPackage['installed_version'] ?? null,
            'resolvable' => $abandonedPackage['resolvable'] ?? false,
            'requires_network' => true,
            'verification_steps' => [
                'composer phpstan',
                'vendor/bin/phpunit tests/',
                'warden:audit --no-notify',
            ],
        ];
    }
}
