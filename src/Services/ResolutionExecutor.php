<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Data\AuditRunReport;
use Dgtlss\Warden\Data\ResolutionExecutionReport;
use Dgtlss\Warden\Data\ResolutionPlan;
use Dgtlss\Warden\Data\ResolutionPlanItem;

class ResolutionExecutor
{
    public function __construct(
        protected ProcessRunner $runner,
        protected AuditManager $auditManager,
        protected AuditHistoryService $historyService,
    ) {
    }

    /**
     * @param array<string, mixed> $options
     */
    public function execute(ResolutionPlan $plan, array $options = []): ResolutionExecutionReport
    {
        $applied = [];
        $skipped = [];

        foreach ($plan->items as $item) {
            if (!$item->canApply((bool) ($options['allow_major'] ?? false))) {
                $skipped[] = [
                    'item' => $item->toArray(),
                    'reason' => $item->isHighRisk() ? 'High-risk items require --allow-major.' : ($item->reason ?? 'Item is not actionable.'),
                ];
                continue;
            }

            $before = $this->snapshot($item->expectedFiles);

            foreach ($item->commands as $command) {
                $result = $this->runner->run(
                    $command['command'],
                    base_path(),
                    (int) config('warden.audits.timeout', 300)
                );

                if (!$result->isSuccessful()) {
                    $applied[] = [
                        'item' => $item->toArray(),
                        'status' => 'failed',
                        'command' => $command['display'],
                        'stdout' => $result->stdout,
                        'stderr' => $result->stderr,
                        'exit_code' => $result->exitCode,
                    ];

                    $this->recordAttempt($plan, $applied, $skipped, [], null, 'failed');

                    return new ResolutionExecutionReport(
                        success: false,
                        applied: $applied,
                        skipped: $skipped,
                        verification: [],
                        failureMessage: sprintf('Resolution command failed: %s', $command['display']),
                    );
                }
            }

            $applied[] = [
                'item' => $item->toArray(),
                'status' => 'applied',
                'before' => $before,
                'after' => $this->snapshot($item->expectedFiles),
            ];
        }

        if ($applied === []) {
            return new ResolutionExecutionReport(
                success: true,
                applied: [],
                skipped: $skipped,
                verification: [],
            );
        }

        $verification = [];

        if (!($options['no_verify'] ?? false)) {
            $verification = $this->runVerification($applied);
            if ($this->hasFailedVerification($verification)) {
                $this->recordAttempt($plan, $applied, $skipped, $verification, null, 'verification_failed');

                return new ResolutionExecutionReport(
                    success: false,
                    applied: $applied,
                    skipped: $skipped,
                    verification: $verification,
                    failureMessage: 'One or more post-apply verification steps failed.',
                );
            }
        }

        $postAuditReport = $this->auditManager->run(
            includeJavascript: $this->shouldIncludeJavascript(),
            force: true,
        );

        $this->recordAttempt($plan, $applied, $skipped, $verification, $postAuditReport, 'applied');

        return new ResolutionExecutionReport(
            success: true,
            applied: $applied,
            skipped: $skipped,
            verification: $verification,
            postAuditReport: $postAuditReport,
        );
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function runVerification(array $applied): array
    {
        $steps = [];
        $requestedSteps = $this->requestedVerificationSteps($applied);

        if (in_array('composer phpstan', $requestedSteps, true) && $this->canRunComposerPhpstan()) {
            $result = $this->runner->run(['composer', 'phpstan'], base_path(), 300);
            $steps[] = $this->verificationStep('composer phpstan', $result);
            if (!$result->isSuccessful()) {
                return $steps;
            }
        }

        if (in_array('vendor/bin/phpunit tests/', $requestedSteps, true) && $this->canRunPhpUnit()) {
            $result = $this->runner->run(['vendor/bin/phpunit', 'tests/'], base_path(), 300);
            $steps[] = $this->verificationStep('vendor/bin/phpunit tests/', $result);
        }

        return $steps;
    }

    /**
     * @return array<string, string|null>
     */
    protected function snapshot(array $files): array
    {
        $snapshot = [];

        foreach ($files as $file) {
            $path = base_path($file);
            $snapshot[$file] = file_exists($path) && is_file($path)
                ? hash_file('sha256', $path)
                : null;
        }

        return $snapshot;
    }

    /**
     * @return array<string, mixed>
     */
    protected function verificationStep(string $name, \Dgtlss\Warden\Data\CommandResult $result): array
    {
        return [
            'name' => $name,
            'success' => $result->isSuccessful(),
            'exit_code' => $result->exitCode,
            'stdout' => $result->stdout,
            'stderr' => $result->stderr,
        ];
    }

    protected function canRunComposerPhpstan(): bool
    {
        $composerJsonPath = base_path('composer.json');
        if (!file_exists($composerJsonPath)) {
            return false;
        }

        $contents = file_get_contents($composerJsonPath);
        $decoded = $contents !== false ? json_decode($contents, true) : null;

        return is_array($decoded)
            && isset($decoded['scripts'])
            && is_array($decoded['scripts'])
            && array_key_exists('phpstan', $decoded['scripts']);
    }

    protected function canRunPhpUnit(): bool
    {
        return file_exists(base_path('vendor/bin/phpunit'))
            && is_dir(base_path('tests'));
    }

    protected function shouldIncludeJavascript(): bool
    {
        return file_exists(base_path('package.json'));
    }

    /**
     * @param array<int, array<string, mixed>> $applied
     * @return array<int, string>
     */
    protected function requestedVerificationSteps(array $applied): array
    {
        $steps = [];

        foreach ($applied as $entry) {
            $item = $entry['item'] ?? null;
            if (!is_array($item)) {
                continue;
            }

            $verificationSteps = $item['verification_steps'] ?? [];
            if (!is_array($verificationSteps)) {
                continue;
            }

            foreach ($verificationSteps as $verificationStep) {
                if (is_string($verificationStep) && $verificationStep !== '') {
                    $steps[] = $verificationStep;
                }
            }
        }

        return array_values(array_unique($steps));
    }

    /**
     * @param array<int, array<string, mixed>> $verification
     */
    protected function hasFailedVerification(array $verification): bool
    {
        foreach ($verification as $step) {
            if (!(bool) ($step['success'] ?? false)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $applied
     * @param array<int, array<string, mixed>> $skipped
     * @param array<int, array<string, mixed>> $verification
     */
    protected function recordAttempt(
        ResolutionPlan $plan,
        array $applied,
        array $skipped,
        array $verification,
        ?AuditRunReport $postAuditReport,
        string $status,
    ): void {
        $this->historyService->appendResolutionAttemptToLatest([
            'mode' => 'apply',
            'status' => $status,
            'created_at' => now()->toIso8601String(),
            'plan_items' => array_map(static fn (ResolutionPlanItem $item): array => $item->toArray(), $plan->items),
            'applied' => $applied,
            'skipped' => $skipped,
            'verification' => $verification,
            'remaining_findings' => $postAuditReport !== null ? count($postAuditReport->findings) : null,
        ]);
    }
}
