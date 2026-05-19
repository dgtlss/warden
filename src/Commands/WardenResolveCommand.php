<?php

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Data\ResolutionExecutionReport;
use Dgtlss\Warden\Data\ResolutionPlan;
use Dgtlss\Warden\Data\ResolutionPlanItem;
use Dgtlss\Warden\Services\AuditHistoryService;
use Dgtlss\Warden\Services\AuditManager;
use Dgtlss\Warden\Services\ProcessRunner;
use Dgtlss\Warden\Services\ResolutionExecutor;
use Dgtlss\Warden\Services\ResolutionPlanner;
use Illuminate\Console\Command;
use function Laravel\Prompts\table;

class WardenResolveCommand extends Command
{
    protected $signature = 'warden:resolve
        {--apply : Apply the proposed resolution plan}
        {--dry-run : Preview the proposed resolution plan}
        {--from-baseline : Unsupported in v1; reserved for future support}
        {--package= : Restrict resolution to one package}
        {--source= : Restrict resolution to composer or npm}
        {--rule= : Restrict resolution to one rule identifier}
        {--with-dev : Include development dependencies in the resolution plan}
        {--allow-major : Allow high-risk major upgrade operations}
        {--branch : Create a codex/warden-resolve-* branch before applying}
        {--no-verify : Skip post-apply verification steps}
        {--force-ci : Allow execution inside CI environments}
        {--allow-dirty : Allow apply mode to run on a dirty working tree}';

    protected $description = 'Preview or apply safe dependency resolutions for active Warden findings.';

    public function __construct(
        protected AuditManager $auditManager,
        protected ResolutionPlanner $resolutionPlanner,
        protected ResolutionExecutor $resolutionExecutor,
        protected ProcessRunner $processRunner,
        protected AuditHistoryService $historyService,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        if (!(bool) config('warden.resolve.enabled', true)) {
            $this->error('Warden auto-resolve is disabled in configuration.');
            return 1;
        }

        if ($this->option('apply') && $this->option('dry-run')) {
            $this->error('Use either preview mode or --apply, not both at the same time.');
            return 1;
        }

        if ($this->option('from-baseline')) {
            $this->warn('Resolving baseline-only findings is not supported in v1. Warden resolves active findings only.');
            return 1;
        }

        $source = $this->option('source');
        if ($source !== null && !in_array($source, ['composer', 'npm'], true)) {
            $this->error('The --source option only supports composer or npm.');
            return 1;
        }

        if ($this->isCi() && !(bool) config('warden.resolve.allow_in_ci', false) && !$this->option('force-ci')) {
            $this->error('warden:resolve is disabled in CI by default. Re-run with --force-ci if you need to override this guard.');
            return 1;
        }

        $includeJavascript = $source === 'npm' || $this->shouldIncludeJavascript();
        $report = $this->auditManager->run(
            includeJavascript: $includeJavascript,
            force: true,
        );
        $plan = $this->resolutionPlanner->buildPlan($report, $this->plannerOptions());

        $this->recordPreviewAttempt($plan);

        if ($plan->items === []) {
            $this->info('No auto-resolvable dependency findings were available for the selected filters.');
            return 0;
        }

        $this->displayPlan($plan);

        if (!$this->option('apply')) {
            return 0;
        }

        if ($plan->applicableItems((bool) $this->option('allow-major')) === []) {
            $this->warn('No plan items are applicable with the current safety flags. Review the preview or re-run with broader options such as --with-dev or --allow-major.');
            return 1;
        }

        if ($this->isDirtyWorkingTree() && !(bool) $this->option('allow-dirty') && !(bool) config('warden.resolve.allow_dirty', false)) {
            $this->error('The working tree has uncommitted changes. Re-run with --allow-dirty if you want Warden to apply fixes anyway.');
            return 1;
        }

        if ($this->shouldCreateBranch()) {
            if (!$this->createBranch()) {
                return 1;
            }
        }

        $executionReport = $this->resolutionExecutor->execute($plan, [
            'allow_major' => (bool) $this->option('allow-major'),
            'no_verify' => !$this->shouldVerify(),
        ]);

        $this->displayExecutionReport($executionReport);

        if (!$executionReport->success) {
            return 1;
        }

        if ($executionReport->postAuditReport !== null && $executionReport->postAuditReport->findings !== []) {
            return 1;
        }

        return 0;
    }

    protected function displayPlan(ResolutionPlan $plan): void
    {
        $rows = array_map(static fn (ResolutionPlanItem $item): array => [
            $item->package,
            $item->source,
            $item->riskLevel,
            $item->actionable ? 'actionable' : 'manual',
            $item->strategy,
        ], $plan->items);

        table(['Package', 'Source', 'Risk', 'Mode', 'Strategy'], $rows);

        foreach ($plan->items as $item) {
            $this->newLine();
            $this->line(sprintf('<options=bold>%s</>', $item->title));
            $this->line('  Package: ' . $item->package);
            $this->line('  Risk: ' . $item->riskLevel);
            $this->line('  Strategy: ' . $item->strategy);
            if ($item->reason !== null) {
                $this->line('  Note: ' . $item->reason);
            }

            if ($item->commands !== []) {
                $this->line('  Commands:');
                foreach ($item->displayCommands() as $command) {
                    $this->line('    - ' . $command);
                }
            }

            $this->line('  Expected files: ' . implode(', ', $item->expectedFiles));
            $this->line('  Verification: ' . implode(', ', $item->verificationSteps));
        }
    }

    protected function displayExecutionReport(ResolutionExecutionReport $report): void
    {
        $this->newLine();
        $this->line('<options=bold>Resolution Summary</>');

        foreach ($report->applied as $applied) {
            /** @var array<string, mixed> $item */
            $item = $applied['item'];
            $status = isset($applied['status']) && is_string($applied['status']) ? $applied['status'] : 'applied';
            $this->line(sprintf('  - %s: %s', $item['package'], $status));
        }

        foreach ($report->skipped as $skipped) {
            /** @var array<string, mixed> $item */
            $item = $skipped['item'];
            $reason = isset($skipped['reason']) && is_string($skipped['reason']) ? $skipped['reason'] : 'skipped';
            $this->line(sprintf('  - %s: skipped (%s)', $item['package'], $reason));
        }

        foreach ($report->verification as $verificationStep) {
            $this->line(sprintf(
                '  - verify %s: %s',
                $verificationStep['name'],
                $verificationStep['success'] ? 'passed' : 'failed'
            ));
        }

        if ($report->failureMessage !== null) {
            $this->error($report->failureMessage);
        }

        if ($report->postAuditReport !== null) {
            $remaining = count($report->postAuditReport->findings);
            if ($remaining === 0) {
                $this->info('All active resolvable findings were cleared by the applied resolution plan.');
            } else {
                $this->warn(sprintf('%d active finding%s remain after apply.', $remaining, $remaining === 1 ? '' : 's'));
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    protected function plannerOptions(): array
    {
        return [
            'source' => $this->option('source') ? (string) $this->option('source') : null,
            'package' => $this->option('package') ? (string) $this->option('package') : null,
            'rule' => $this->option('rule') ? (string) $this->option('rule') : null,
            'with_dev' => (bool) $this->option('with-dev'),
            'allow_major' => (bool) $this->option('allow-major'),
        ];
    }

    protected function shouldIncludeJavascript(): bool
    {
        return file_exists(base_path('package.json'));
    }

    protected function isCi(): bool
    {
        return getenv('CI') !== false;
    }

    protected function shouldVerify(): bool
    {
        if ($this->option('no-verify')) {
            return false;
        }

        return (bool) config('warden.resolve.default_verify', true);
    }

    protected function shouldCreateBranch(): bool
    {
        return (bool) $this->option('branch') || (bool) config('warden.resolve.auto_branch', false);
    }

    protected function isDirtyWorkingTree(): bool
    {
        $insideWorkTree = $this->processRunner->run(['git', 'rev-parse', '--is-inside-work-tree'], base_path(), 15);
        if (!$insideWorkTree->isSuccessful()) {
            return false;
        }

        $status = $this->processRunner->run(['git', 'status', '--short'], base_path(), 15);

        return trim($status->stdout) !== '';
    }

    protected function createBranch(): bool
    {
        $branchName = sprintf('codex/warden-resolve-%s', now()->format('Ymd-His'));
        $result = $this->processRunner->run(['git', 'checkout', '-b', $branchName], base_path(), 30);

        if (!$result->isSuccessful()) {
            $this->error('Failed to create branch ' . $branchName . '.');
            if ($result->stderr !== '') {
                $this->error(trim($result->stderr));
            }

            return false;
        }

        $this->info('Created branch ' . $branchName . ' for Warden resolution changes.');

        return true;
    }

    protected function recordPreviewAttempt(ResolutionPlan $plan): void
    {
        $this->historyService->appendResolutionAttemptToLatest([
            'mode' => $this->option('apply') ? 'apply-preview' : 'preview',
            'created_at' => now()->toIso8601String(),
            'filters' => $plan->filters,
            'item_count' => count($plan->items),
            'items' => array_map(static fn (ResolutionPlanItem $item): array => $item->toArray(), $plan->items),
        ]);
    }
}
