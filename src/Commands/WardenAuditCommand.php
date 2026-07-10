<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Commands;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\Services\AuditRunner;
use Dgtlss\Warden\Services\NotificationDispatcher;
use Dgtlss\Warden\Services\ReportFormatterFactory;
use Dgtlss\Warden\Services\SuppressionService;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Illuminate\Console\Command;
use Throwable;

final class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit
        {--profile=ci : Audit profile (ci|production|local)}
        {--scope=production : Dependency scope (production|all)}
        {--fail-on=low : Failure threshold (low|medium|high|critical|never)}
        {--format=console : Report format (console|json|github|gitlab|sarif|junit)}
        {--output-file=- : Write the report to stdout (-) or a file}
        {--only= : Comma-separated audit IDs to run}
        {--skip= : Comma-separated audit IDs to skip}
        {--notify : Send opt-in notifications after report generation}';

    protected $description = 'Run deterministic security audits for a Laravel deployment.';

    public function __construct(
        private readonly AuditRunner $auditRunner,
        private readonly SuppressionService $suppressionService,
        private readonly ReportFormatterFactory $reportFormatterFactory,
        private readonly NotificationDispatcher $notificationDispatcher,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $profile = (string) $this->option('profile');
        $scope = (string) $this->option('scope');
        $failOn = (string) $this->option('fail-on');
        $format = (string) $this->option('format');
        $outputFile = (string) $this->option('output-file');
        $only = $this->csvOption('only');
        $skip = $this->csvOption('skip');
        $timeout = config('warden.audits.timeout', 300);

        $validationError = $this->validateOptions($profile, $scope, $failOn, $format, $outputFile, $timeout, $only, $skip);
        if ($validationError !== null) {
            return $this->renderInvalidConfiguration($validationError, $profile, $scope, $format, $outputFile);
        }

        $auditContext = new AuditContext(
            profile: $profile,
            scope: $scope,
            timeout: (int) $timeout,
            only: $only,
            skip: $skip,
        );
        $progress = $format === 'console' && $outputFile === '-'
            ? function (string $audit, string $status, ?float $duration): void {
                if ($status !== 'running') {
                    $this->line(sprintf('%s %s (%sms)', $status === 'done' ? '✓' : '✗', $audit, number_format($duration ?? 0, 1)));
                }
            }
            : null;

        $scannedAt = CarbonImmutable::now();
        $suppressionErrors = $this->suppressionService->errors(now: $scannedAt);
        $auditReport = $suppressionErrors === []
            ? $this->suppressionService->apply($this->auditRunner->run($auditContext, $progress))
            : new AuditReport($auditContext, [], configurationErrors: $suppressionErrors, scannedAt: $scannedAt);

        try {
            $rendered = $this->reportFormatterFactory->make($format)->format($auditReport);
        } catch (Throwable $throwable) {
            $this->writeError('Report generation failed: ' . $throwable->getMessage());

            return 2;
        }

        if (!$this->writeReport($rendered, $outputFile)) {
            return 2;
        }

        if ((bool) $this->option('notify')) {
            foreach ($this->notificationDispatcher->send($auditReport) as $warning) {
                $this->writeError($warning);
            }
        }

        return $auditReport->exitCode($failOn);
    }

    /** @return list<string> */
    private function csvOption(string $name): array
    {
        $value = $this->option($name);
        if (!is_string($value) || trim($value) === '') {
            return [];
        }

        $items = array_map('trim', explode(',', $value));
        $items = array_values(array_unique(array_filter($items, static fn (string $item): bool => $item !== '')));
        sort($items);

        return $items;
    }

    /**
     * @param list<string> $only
     * @param list<string> $skip
     */
    private function validateOptions(
        string $profile,
        string $scope,
        string $failOn,
        string $format,
        string $outputFile,
        mixed $timeout,
        array $only,
        array $skip,
    ): ?string {
        $valid = [
            'profile' => ['ci', 'production', 'local'],
            'scope' => ['production', 'all'],
            'fail-on' => ['low', 'medium', 'high', 'critical', 'never'],
            'format' => ['console', 'json', 'github', 'gitlab', 'sarif', 'junit'],
        ];

        foreach (['profile' => $profile, 'scope' => $scope, 'fail-on' => $failOn, 'format' => $format] as $option => $value) {
            if (!in_array($value, $valid[$option], true)) {
                return sprintf('Invalid --%s value "%s". Expected one of: %s.', $option, $value, implode(', ', $valid[$option]));
            }
        }

        if ($outputFile === '') {
            return '--output-file cannot be empty.';
        }

        if (!is_int($timeout) || $timeout < 1 || $timeout > 3600) {
            return 'warden.audits.timeout must be an integer between 1 and 3600 seconds.';
        }

        $overlap = array_intersect($only, $skip);
        if ($overlap !== []) {
            return sprintf('The same audit cannot be selected and skipped: %s.', implode(', ', $overlap));
        }

        if ($only !== [] || $skip !== []) {
            $available = $this->auditRunner->availableAuditIds();
            foreach ([...$only, ...$skip] as $audit) {
                if (!in_array($audit, $available, true)) {
                    return sprintf('Unknown audit "%s". Available audits: %s.', $audit, implode(', ', $available));
                }
            }
        }

        return null;
    }

    private function renderInvalidConfiguration(
        string $message,
        string $profile,
        string $scope,
        string $format,
        string $outputFile,
    ): int {
        $this->writeError($message);
        if (!in_array($format, ['json', 'github', 'gitlab', 'sarif', 'junit'], true)) {
            return 2;
        }

        $auditContext = new AuditContext(
            profile: in_array($profile, ['ci', 'production', 'local'], true) ? $profile : 'ci',
            scope: in_array($scope, ['production', 'all'], true) ? $scope : 'production',
        );
        $auditReport = new AuditReport(
            $auditContext,
            [],
            configurationErrors: [new AuditError('configuration', 'invalid_option', $message)],
            scannedAt: CarbonImmutable::now(),
        );
        $rendered = $this->reportFormatterFactory->make($format)->format($auditReport);
        $this->writeReport($rendered, $outputFile === '' ? '-' : $outputFile);

        return 2;
    }

    private function writeReport(string $report, string $outputFile): bool
    {
        if ($outputFile === '-') {
            $this->output->write($report);

            return true;
        }

        $path = str_starts_with($outputFile, DIRECTORY_SEPARATOR) ? $outputFile : base_path($outputFile);
        if (@file_put_contents($path, $report) === false) {
            $this->writeError(sprintf('Unable to write report to %s.', $outputFile));

            return false;
        }

        return true;
    }

    private function writeError(string $message): void
    {
        fwrite(STDERR, $message . PHP_EOL);
    }
}
