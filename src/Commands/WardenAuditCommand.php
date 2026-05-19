<?php

namespace Dgtlss\Warden\Commands;

use Dgtlss\Warden\Data\AuditResult;
use Dgtlss\Warden\Data\AuditRunReport;
use Dgtlss\Warden\Notifications\Channels\DiscordChannel;
use Dgtlss\Warden\Notifications\Channels\EmailChannel;
use Dgtlss\Warden\Notifications\Channels\SlackChannel;
use Dgtlss\Warden\Notifications\Channels\TeamsChannel;
use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\AuditManager;
use Dgtlss\Warden\Services\ReportFormatter;
use Dgtlss\Warden\Services\ResolutionPlanner;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use function Laravel\Prompts\info;
use function Laravel\Prompts\table;

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit
    {--no-notify : Run the audit without sending notifications (replaces --silent)}
    {--npm : Run the npm audit}
    {--ignore-abandoned : Ignore abandoned packages, without throwing an error}
    {--output= : Output format (json|github|gitlab|jenkins|sarif|cyclonedx|markdown|html)}
    {--severity= : Filter by severity level (low|medium|high|critical)}
    {--force : Force cache refresh and ignore cached results}';

    protected $description = 'Run security audits on your application dependencies and configuration.';

    public function __construct(
        protected AuditCacheService $cacheService,
        protected AuditManager $auditManager,
        protected ReportFormatter $reportFormatter,
        protected ResolutionPlanner $resolutionPlanner,
    ) {
        parent::__construct();
    }

    protected function shouldSuppressNotifications(): bool
    {
        if ($this->option('no-notify')) {
            return true;
        }

        return $this->output->isSilent();
    }

    public function handle(): int
    {
        $outputFormat = $this->option('output');
        $isMachineOutput = $outputFormat !== null;

        if (!$isMachineOutput) {
            $this->displayVersion();
        }

        if ($this->option('force')) {
            $this->cacheService->clearCache();
            if (!$isMachineOutput) {
                $this->info('Cache cleared.');
            }
        }

        $warnings = [];
        $progress = $isMachineOutput ? null : function (string $name, string $status, ?float $durationMs): void {
            $this->renderAuditProgress($name, $status, $durationMs);
        };

        $report = $this->auditManager->run(
            includeJavascript: (bool) $this->option('npm'),
            force: (bool) $this->option('force'),
            onWarning: function (string $warning) use (&$warnings): void {
                $warnings[] = $warning;
            },
            onProgress: $progress,
        );

        foreach ($warnings as $warning) {
            if (!$isMachineOutput) {
                $this->warn($warning);
            }
        }

        $findings = $report->findings;
        $totalBeforeFilter = count($findings);
        $severityOption = null;

        if ($this->option('severity')) {
            $severityOption = (string) $this->option('severity');
            $findings = $this->filterBySeverity($findings, $severityOption);
        }

        $filteredReport = new AuditRunReport(
            results: $report->results,
            findings: array_values($findings),
            suppressedFindings: $report->suppressedFindings,
            abandonedPackages: $report->abandonedPackages,
            hasFailures: $report->hasFailures,
            durationMs: $report->durationMs,
            profile: $report->profile,
            metadata: $report->metadata,
        );

        if ($outputFormat) {
            $this->outputFormattedResults($filteredReport, (string) $outputFormat);
            return $filteredReport->findings === [] ? ($filteredReport->hasFailures ? 2 : 0) : 1;
        }

        $this->displayAuditFailures($filteredReport);
        $this->handleAbandonedPackages($filteredReport->abandonedPackages);
        $this->newLine();

        if ($filteredReport->findings !== []) {
            $this->displayFindings($filteredReport->findings);
            $this->displayResolveSuggestion($filteredReport);

            if (!$this->shouldSuppressNotifications()) {
                $this->sendNotifications($filteredReport->findings);
            }

            return 1;
        }

        $filtered = $totalBeforeFilter - count($filteredReport->findings);
        if ($filtered > 0 && $severityOption !== null) {
            info(sprintf('No issues at %s severity or above (%d lower-severity %s filtered).', $severityOption, $filtered, $filtered === 1 ? 'issue' : 'issues'));
        } elseif ($report->suppressedFindings !== []) {
            info(sprintf('✅ No active security issues found (%d finding%s suppressed by baseline or policy).', count($report->suppressedFindings), count($report->suppressedFindings) === 1 ? '' : 's'));
        } else {
            info('✅ No security issues found.');
        }

        $this->displayResolveSuggestion($filteredReport);

        return $filteredReport->hasFailures ? 2 : 0;
    }

    protected function displayResolveSuggestion(AuditRunReport $report): void
    {
        if ($this->isRunningInCi()) {
            return;
        }

        $plan = $this->resolutionPlanner->buildPlan($report);
        if (!$plan->hasResolvableItems()) {
            return;
        }

        $sources = $plan->sources();
        $command = 'php artisan warden:resolve';

        if (count($sources) === 1) {
            $command .= ' --source=' . $sources[0];
        }

        $this->newLine();
        $this->info('Resolvable dependency issues detected. Next step: ' . $command);
    }

    protected function displayVersion(): void
    {
        $this->newLine();
        $this->line(sprintf('  <fg=cyan;options=bold>Warden</> <fg=white>v%s</>', $this->getWardenVersion()));
        $this->newLine();
    }

    protected function renderAuditProgress(string $name, string $status, ?float $durationMs): void
    {
        $label = ucfirst($name);

        if ($status === 'running') {
            $this->output->write(sprintf('  <fg=blue>⏳</> Running <options=bold>%s</> audit ...', $label));
            return;
        }

        if (stream_isatty(STDOUT)) {
            $this->output->write("\r\033[2K");
        } else {
            $this->newLine();
        }

        $duration = $durationMs !== null ? sprintf(' <fg=gray>(%sms)</>', number_format($durationMs, 0)) : '';

        if ($status === 'done') {
            $this->line(sprintf('  <fg=green>✓</> %s audit%s', $label, $duration));
        } else {
            $this->line(sprintf('  <fg=red>✗</> %s audit <fg=red>failed</>%s', $label, $duration));
        }
    }

    protected function displayAuditFailures(AuditRunReport $report): void
    {
        foreach ($report->results as $result) {
            if ($result->success) {
                continue;
            }

            $this->error($result->auditName . ' audit failed to run.');

            foreach ($result->findingsToArray() as $finding) {
                if (isset($finding['error']) && is_string($finding['error']) && $finding['error'] !== '') {
                    $this->error('Error: ' . $finding['error']);
                    break;
                }
            }
        }
    }

    protected function handleAbandonedPackages(array $abandonedPackages): void
    {
        if ($abandonedPackages === []) {
            return;
        }

        if ($this->option('ignore-abandoned')) {
            $this->warn(count($abandonedPackages) . ' abandoned packages found (ignored due to --ignore-abandoned flag)');
            return;
        }

        $this->warn(count($abandonedPackages) . ' abandoned packages found.');

        $rows = [];
        foreach ($abandonedPackages as $abandonedPackage) {
            $rows[] = [
                $abandonedPackage['package'],
                $abandonedPackage['replacement'] ?? 'No replacement suggested',
            ];
        }

        table(headers: ['Package', 'Recommended Replacement'], rows: $rows);

        if (!$this->shouldSuppressNotifications()) {
            $this->sendAbandonedPackagesNotification($abandonedPackages);
        }
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     */
    protected function displayFindings(array $findings): void
    {
        $count = count($findings);
        $this->error($count . ' security ' . ($count === 1 ? 'issue' : 'issues') . ' found.');

        $hasCveData = collect($findings)->contains(fn ($f) => !empty($f['cve']));
        $headers = ['Source', 'Package', 'Title', 'Severity'];
        if ($hasCveData) {
            $headers = array_merge($headers, ['CVE', 'Affected Versions']);
        }

        $rows = [];
        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'unknown';
            $severityDisplay = match ($severity) {
                'critical' => '🔴 Critical',
                'high' => '🟠 High',
                'medium' => '🟡 Medium',
                'low' => '🟢 Low',
                default => $severity,
            };

            $row = [
                $finding['source'],
                $finding['package'],
                $finding['title'],
                $severityDisplay,
            ];

            if ($hasCveData) {
                $row[] = $finding['cve'] ?? '-';
                $row[] = $finding['affected_versions'] ?? '-';
            }

            $rows[] = $row;
        }

        table(headers: $headers, rows: $rows);
    }

    /**
     * @param array<array<string, mixed>> $findings
     */
    protected function sendNotifications(array $findings): void
    {
        $channels = $this->getNotificationChannels();
        $sent = false;

        foreach ($channels as $channel) {
            try {
                $channel->send($findings);
                $this->info('Notification sent via ' . $channel->getName());
                $sent = true;
            } catch (\Exception $e) {
                $this->warn(sprintf('Failed to send notification via %s: %s', $channel->getName(), $e->getMessage()));
            }
        }

        $legacySent = $this->sendLegacyNotifications($findings);
        $sent = $sent || $legacySent;

        if (!$sent) {
            $this->warn('No notification channels configured. Set up Slack, Discord, Teams, or Email in config/warden.php.');
        }
    }

    /**
     * @return array<NotificationChannel>
     */
    protected function getNotificationChannels(): array
    {
        $channels = [];

        foreach ([new SlackChannel(), new DiscordChannel(), new EmailChannel(), new TeamsChannel()] as $channel) {
            if ($channel->isConfigured()) {
                $channels[] = $channel;
            }
        }

        return $channels;
    }

    /**
     * @param array<array<string, mixed>> $findings
     */
    protected function sendLegacyNotifications(array $findings): bool
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');
        $sent = false;

        if ($webhookUrl) {
            $this->sendWebhookNotification((string) $webhookUrl, $findings);
            $sent = true;
        }

        if ($emailRecipients) {
            $recipients = is_string($emailRecipients) ? explode(',', $emailRecipients) : $emailRecipients;
            $this->sendEmailReport($findings, $recipients);
            $sent = true;
        }

        return $sent;
    }

    /**
     * @param array<array<string, mixed>> $findings
     */
    protected function sendWebhookNotification(string $webhookUrl, array $findings): void
    {
        Http::post($webhookUrl, ['text' => $this->formatFindingsForWebhook($findings)]);
    }

    /**
     * @param array<array<string, mixed>> $findings
     */
    protected function formatFindingsForWebhook(array $findings): string
    {
        $message = "🚨 *Warden Security Audit Report* 🚨\n\n";
        $message .= count($findings) . " vulnerabilities found:\n\n";

        foreach ($findings as $finding) {
            $message .= "• *{$finding['package']}*: {$finding['title']} ({$finding['severity']})\n";
            if (!empty($finding['cve'])) {
                $message .= sprintf('  CVE: %s - https://www.cve.org/CVERecord?id=%s%s', $finding['cve'], $finding['cve'], PHP_EOL);
            }

            $message .= "\n";
        }

        return $message;
    }

    /**
     * @param array<array<string, mixed>> $report
     * @param array<string> $emailRecipients
     */
    protected function sendEmailReport(array $report, array $emailRecipients): void
    {
        Mail::send('warden::mail.report', ['report' => $report], function ($message) use ($emailRecipients): void {
            $message->to($emailRecipients)->subject('Warden Audit Report');
        });
    }

    /**
     * @param array<array<string, mixed>> $abandonedPackages
     */
    protected function sendAbandonedPackagesNotification(array $abandonedPackages): void
    {
        $channels = $this->getNotificationChannels();

        foreach ($channels as $channel) {
            try {
                $channel->sendAbandonedPackages($abandonedPackages);
                $this->info('Abandoned packages notification sent via ' . $channel->getName());
            } catch (\Exception $e) {
                $this->warn(sprintf('Failed to send abandoned packages notification via %s: %s', $channel->getName(), $e->getMessage()));
            }
        }

        $this->sendLegacyAbandonedPackagesNotification($abandonedPackages);
    }

    /**
     * @param array<array<string, mixed>> $abandonedPackages
     */
    protected function sendLegacyAbandonedPackagesNotification(array $abandonedPackages): void
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        $message = "The following packages are marked as abandoned:\n\n";
        foreach ($abandonedPackages as $abandonedPackage) {
            $message .= '- ' . $abandonedPackage['package'];
            if (!empty($abandonedPackage['replacement'])) {
                $message .= sprintf(' (Recommended replacement: %s)', $abandonedPackage['replacement']);
            }

            $message .= "\n";
        }

        if ($webhookUrl) {
            Http::post((string) $webhookUrl, ['text' => $message]);
        }

        if ($emailRecipients) {
            $recipients = is_string($emailRecipients) ? explode(',', $emailRecipients) : $emailRecipients;
            Mail::raw($message, function ($message) use ($recipients): void {
                $message->to($recipients)->subject('Warden Audit - Abandoned Packages Found');
            });
        }
    }

    /**
     * @param array<array<string, mixed>> $findings
     * @return array<int, array<string, mixed>>
     */
    protected function filterBySeverity(array $findings, string $minSeverity): array
    {
        $severityLevels = [
            'low' => 1,
            'medium' => 2,
            'high' => 3,
            'critical' => 4,
        ];

        $minLevel = $severityLevels[$minSeverity] ?? 1;

        return array_values(array_filter($findings, function ($finding) use ($severityLevels, $minLevel) {
            $findingSeverity = $finding['severity'] ?? 'low';
            $findingLevel = $severityLevels[$findingSeverity] ?? 1;
            return $findingLevel >= $minLevel;
        }));
    }

    protected function outputFormattedResults(AuditRunReport $report, string $format): void
    {
        switch ($format) {
            case 'json':
                $this->output->writeln(json_encode($this->reportFormatter->json($report), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                break;
            case 'github':
                foreach ($this->reportFormatter->github($report) as $line) {
                    $this->output->writeln($line);
                }
                break;
            case 'gitlab':
                $this->output->writeln(json_encode($this->reportFormatter->gitlab($report), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                break;
            case 'jenkins':
                $this->output->writeln(json_encode($this->reportFormatter->jenkins($report), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                break;
            case 'sarif':
                $this->output->writeln(json_encode($this->reportFormatter->sarif($report), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                break;
            case 'cyclonedx':
                $this->output->writeln(json_encode($this->reportFormatter->cyclonedx($report), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                break;
            case 'markdown':
                $this->output->writeln($this->reportFormatter->markdown($report));
                break;
            case 'html':
                $this->output->writeln($this->reportFormatter->html($report));
                break;
            default:
                $this->error('Unsupported output format: ' . $format);
                $this->info('Supported formats: json, github, gitlab, jenkins, sarif, cyclonedx, markdown, html');
                break;
        }
    }

    protected function getWardenVersion(): string
    {
        $composerPath = dirname(__DIR__, 2) . '/composer.json';

        if (!file_exists($composerPath)) {
            return 'unknown';
        }

        $composerJsonContent = file_get_contents($composerPath);
        if ($composerJsonContent === false) {
            return 'unknown';
        }

        $composerJson = json_decode($composerJsonContent, true);
        if (!is_array($composerJson) || !isset($composerJson['version'])) {
            return 'unknown';
        }

        return $composerJson['version'];
    }

    protected function isRunningInCi(): bool
    {
        return getenv('CI') !== false;
    }
}
