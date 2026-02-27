<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Collection;
use Carbon\Carbon;
use Symfony\Component\Process\Process;
use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Services\Audits\EnvAuditService;
use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\AuditExecutor;
use Dgtlss\Warden\Notifications\Channels\SlackChannel;
use Dgtlss\Warden\Notifications\Channels\DiscordChannel;
use Dgtlss\Warden\Notifications\Channels\EmailChannel;
use Dgtlss\Warden\Notifications\Channels\TeamsChannel;
use Dgtlss\Warden\Contracts\CustomAudit;
use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\Services\CustomAuditWrapper;
use function Laravel\Prompts\info;
use function Laravel\Prompts\table;

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit 
    {--no-notify : Run the audit without sending notifications (replaces --silent)} 
    {--npm : Run the npm audit}
    {--ignore-abandoned : Ignore abandoned packages, without throwing an error}
    {--output= : Output format (json|github|gitlab|jenkins)}
    {--severity= : Filter by severity level (low|medium|high|critical)}
    {--force : Force cache refresh and ignore cached results}';

    protected $description = 'Run security audits on your application dependencies and configuration.';

    protected AuditCacheService $cacheService;

    protected AuditExecutor $executor;

    public function __construct(AuditCacheService $auditCacheService, AuditExecutor $auditExecutor)
    {
        parent::__construct();
        $this->cacheService = $auditCacheService;
        $this->executor = $auditExecutor;
    }

    /**
     * Check whether notifications should be suppressed.
     *
     * Supports both the new --no-notify flag and the legacy --silent flag.
     * On Symfony Console 7.2+ (Laravel 11+), --silent is a framework-level
     * option that also suppresses output. We detect it via output verbosity
     * so that existing users passing --silent still get notification suppression.
     */
    protected function shouldSuppressNotifications(): bool
    {
        if ($this->option('no-notify')) {
            return true;
        }

        if ($this->output->isSilent()) {
            return true;
        }

        return false;
    }

    /**
     * Execute the console command.
     *
     * @return int Exit code: 0 for success, 1 for vulnerabilities found, 2 for audit failures
     */
    public function handle(): int
    {
        $isMachineOutput = $this->option('output') !== null;

        if (!$isMachineOutput) {
            $this->displayVersion();
        }

        if ($this->option('force')) {
            $this->cacheService->clearCache();
            if (!$isMachineOutput) {
                $this->info('Cache cleared.');
            }
        }

        $useParallel = config('warden.audits.parallel_execution', true);

        if ($useParallel) {
            return $this->runParallelAudits($isMachineOutput);
        }

        return $this->runSequentialAudits($isMachineOutput);
    }

    protected function runParallelAudits(bool $isMachineOutput = false): int
    {
        $auditServices = $this->initializeAuditServices();

        foreach ($auditServices as $auditService) {
            $this->executor->addAudit($auditService);
        }

        $progress = $isMachineOutput ? null : function (string $name, string $status, ?float $durationMs): void {
            $this->renderAuditProgress($name, $status, $durationMs);
        };

        $results = $this->executor->execute($progress);

        // Collect findings and abandoned packages
        $allFindings = [];
        $abandonedPackages = [];
        $hasFailures = false;

        foreach ($results as $result) {
            if (!$result['success']) {
                $this->handleAuditFailure($result['service']);
                $hasFailures = true;
                continue;
            }

            if (!empty($result['findings'])) {
                $allFindings = array_merge($allFindings, $result['findings']);
            }

            // Collect abandoned packages from composer audit
            if ($result['service'] instanceof ComposerAuditService) {
                $abandonedPackages = $result['service']->getAbandonedPackages();
            }
        }

        return $this->processResults($allFindings, $abandonedPackages, $hasFailures);
    }

    protected function runSequentialAudits(bool $isMachineOutput = false): int
    {
        $auditServices = $this->initializeAuditServices();
        $hasFailures = false;
        $allFindings = [];
        $abandonedPackages = [];

        foreach ($auditServices as $auditService) {
            $auditName = $auditService->getName();

            // Check cache first (unless force is used)
            if (!$this->option('force') && $this->cacheService->hasRecentAudit($auditName)) {
                $this->info(sprintf('Using cached results for %s audit...', $auditName));
                $cached = $this->cacheService->getCachedResult($auditName);
                if (!empty($cached['result'])) {
                    $allFindings = array_merge($allFindings, $cached['result']);
                }

                continue;
            }

            $this->info(sprintf('Running %s audit...', $auditName));

            if (!$auditService->run()) {
                $this->handleAuditFailure($auditService);
                $hasFailures = true;
                continue;
            }

            $findings = $auditService->getFindings();
            if (!empty($findings)) {
                $allFindings = array_merge($allFindings, $findings);
                // Cache the results
                $this->cacheService->storeResult($auditName, $findings);
            }

            // Collect abandoned packages
            if ($auditService instanceof ComposerAuditService) {
                $abandonedPackages = $auditService->getAbandonedPackages();
            }
        }

        return $this->processResults($allFindings, $abandonedPackages, $hasFailures);
    }

    protected function processResults(array $allFindings, array $abandonedPackages, bool $hasFailures): int
    {
        $totalBeforeFilter = count($allFindings);
        $severityOption = null;

        // Apply severity filtering if specified
        if ($this->option('severity')) {
            $severityOption = (string) $this->option('severity');
            $allFindings = $this->filterBySeverity($allFindings, $severityOption);
        }

        $this->handleAbandonedPackages($abandonedPackages);

        $outputFormat = $this->option('output');
        if ($outputFormat) {
            $this->outputFormattedResults($allFindings, (string) $outputFormat);
            return $allFindings === [] ? ($hasFailures ? 2 : 0) : 1;
        }

        $this->newLine();

        if ($allFindings !== []) {
            $this->displayFindings($allFindings);

            if (!$this->shouldSuppressNotifications()) {
                $this->sendNotifications($allFindings);
            }

            return 1;
        }

        $filtered = $totalBeforeFilter - count($allFindings);
        if ($filtered > 0 && $severityOption !== null) {
            info(sprintf('No issues at %s severity or above (%d lower-severity %s filtered).', $severityOption, $filtered, $filtered === 1 ? 'issue' : 'issues'));
        } else {
            info('✅ No security issues found.');
        }

        return $hasFailures ? 2 : 0;
    }

    /**
     * Display the current version of Warden.
     */
    protected function displayVersion(): void
    {
        $this->newLine();
        $this->line(sprintf('  <fg=cyan;options=bold>Warden</> <fg=white>v%s</>', $this->getWardenVersion()));
        $this->newLine();
    }

    /**
     * Render per-audit progress line.
     */
    protected function renderAuditProgress(string $name, string $status, ?float $durationMs): void
    {
        $label = ucfirst($name);

        if ($status === 'running') {
            $this->output->write(sprintf('  <fg=blue>⏳</> Running <options=bold>%s</> audit ...', $label));
            return;
        }

        // Overwrite the "running" line if terminal supports it
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

    /**
     * Initialize and return all audit services based on command options.
     *
     * @return array<int, object> Array of audit service instances
     */
    protected function initializeAuditServices(): array
    {
        $services = [
            app(ComposerAuditService::class),
            app(EnvAuditService::class),
            app(StorageAuditService::class),
            app(DebugModeAuditService::class),
        ];

        if ($this->option('npm')) {
            $services[] = app(NpmAuditService::class);
        }

        // Load custom audits from configuration
        $customAudits = config('warden.custom_audits', []);
        foreach ($customAudits as $customAuditClass) {
            if (!class_exists($customAuditClass)) {
                $this->warn('Custom audit class not found: ' . $customAuditClass);
                continue;
            }

            try {
                $customAudit = app()->make($customAuditClass);
                if (!$customAudit instanceof CustomAudit) {
                    $this->warn(sprintf('Custom audit %s must implement ', $customAuditClass) . CustomAudit::class);
                    continue;
                }

                if (!$customAudit->shouldRun()) {
                    continue;
                }

                $services[] = new CustomAuditWrapper($customAudit);
                $this->info('Loaded custom audit: ' . $customAudit->getName());
            } catch (\Exception $e) {
                $this->warn(sprintf('Failed to load custom audit %s: %s', $customAuditClass, $e->getMessage()));
            }
        }

        return $services;
    }

    /**
     * Handle a failed audit service.
     *
     * @param object $service The audit service that failed
     */
    protected function handleAuditFailure(object $service): void
    {
        $serviceName = $service instanceof \Dgtlss\Warden\Services\Audits\AbstractAuditService || $service instanceof CustomAuditWrapper
            ? $service->getName()
            : 'Unknown service';
        $this->error($serviceName . ' audit failed to run.');
        if ($service instanceof ComposerAuditService) {
            $findings = $service->getFindings();
            $error = Collection::make($findings)->last()['error'] ?? 'Unknown error';
            $this->error("Error: " . $error);
        }
    }

    /**
     * Process and display abandoned packages information.
     *
     * @param array $abandonedPackages List of abandoned packages
     */
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

        $headers = ['Package', 'Recommended Replacement'];
        $rows = [];

        foreach ($abandonedPackages as $abandonedPackage) {
            $rows[] = [
                $abandonedPackage['package'],
                $abandonedPackage['replacement'] ?? 'No replacement suggested'
            ];
        }

        table(
            headers: $headers,
            rows: $rows
        );

        if (!$this->shouldSuppressNotifications()) {
            $this->sendAbandonedPackagesNotification($abandonedPackages);
        }
    }

    /**
     * Display audit findings in a formatted table.
     *
     * @param array $findings List of vulnerability findings
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
                $cve = $finding['cve'] ?? null;
                $row[] = $cve ?: '-';
                $row[] = $finding['affected_versions'] ?? '-';
            }

            $rows[] = $row;
        }

        table(
            headers: $headers,
            rows: $rows
        );
    }

    /**
     * Prepare a structured report from advisory data.
     *
     * @param array<string, array<array<string, mixed>>> $advisories Advisory data organized by package
     * @return array<string, array<array<string, mixed>>> Structured report data
     */
    protected function prepareReport(array $advisories): array
    {
        $reportData = [];
        foreach ($advisories as $package => $issues) {
            $packageIssues = [];
            foreach ($issues as $issue) {
                $packageIssues[] = [
                    'title' => $issue['title'],
                    'cve' => $issue['cve'],
                    'link' => 'https://www.cve.org/CVERecord?id=' . $issue['cve'],
                    'affected_versions' => $issue['affected_versions']
                ];
            }

            $reportData[$package] = $packageIssues;
        }

        return $reportData;
    }

    /**
     * Send notifications about vulnerabilities through configured channels.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
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
     * Get configured notification channels.
     *
     * @return array<NotificationChannel>
     */
    protected function getNotificationChannels(): array
    {
        $channels = [];

        // Slack channel
        $slackChannel = new SlackChannel();
        if ($slackChannel->isConfigured()) {
            $channels[] = $slackChannel;
        }

        // Discord channel
        $discordChannel = new DiscordChannel();
        if ($discordChannel->isConfigured()) {
            $channels[] = $discordChannel;
        }

        // Email channel
        $emailChannel = new EmailChannel();
        if ($emailChannel->isConfigured()) {
            $channels[] = $emailChannel;
        }

        // Microsoft Teams channel
        $teamsChannel = new TeamsChannel();
        if ($teamsChannel->isConfigured()) {
            $channels[] = $teamsChannel;
        }

        return $channels;
    }

    /**
     * Send notifications via legacy webhook and email methods.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     */
    protected function sendLegacyNotifications(array $findings): bool
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');
        $sent = false;

        if ($webhookUrl) {
            $this->sendWebhookNotification($webhookUrl, $findings);
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
     * Send a webhook notification with audit findings.
     *
     * @param string $webhookUrl The URL to send webhook to
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     */
    protected function sendWebhookNotification(string $webhookUrl, array $findings): void
    {
        // Format findings for webhook
        $formattedReport = $this->formatFindingsForWebhook($findings);
        Http::post($webhookUrl, ['text' => $formattedReport]);
    }

    /**
     * Format findings into a readable message for webhook notifications.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     * @return string Formatted message
     */
    protected function formatFindingsForWebhook(array $findings): string
    {
        // Implement a better formatting for webhook notifications
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
     * Send an email report with audit findings.
     *
     * @param array<array<string, mixed>> $report Report data to include in email
     * @param array<string> $emailRecipients Recipients of email
     */
    protected function sendEmailReport(array $report, array $emailRecipients): void
    {
        Mail::send('warden::mail.report', ['report' => $report], function ($message) use ($emailRecipients): void {
            $message->to($emailRecipients)
                    ->subject('Warden Audit Report');
        });
    }

    /**
     * Send notifications about abandoned packages.
     *
     * @param array<array<string, mixed>> $abandonedPackages List of abandoned packages
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

        // Legacy support
        $this->sendLegacyAbandonedPackagesNotification($abandonedPackages);
    }

    /**
     * Send legacy notifications for abandoned packages.
     *
     * @param array<array<string, mixed>> $abandonedPackages List of abandoned packages
     */
    protected function sendLegacyAbandonedPackagesNotification(array $abandonedPackages): void
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        $message = "The following packages are marked as abandoned:\n\n";
        foreach ($abandonedPackages as $abandonedPackage) {
            $message .= '- ' . $abandonedPackage['package'];
            if ($abandonedPackage['replacement']) {
                $message .= sprintf(' (Recommended replacement: %s)', $abandonedPackage['replacement']);
            }

            $message .= "\n";
        }

        if ($webhookUrl) {
            Http::post($webhookUrl, ['text' => $message]);
        }

        if ($emailRecipients) {
            $recipients = is_string($emailRecipients) ? explode(',', $emailRecipients) : $emailRecipients;
            Mail::raw($message, function ($message) use ($recipients): void {
                $message->to($recipients)
                        ->subject('Warden Audit - Abandoned Packages Found');
            });
        }
    }

    /**
     * Filter findings by severity level.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     * @param string $minSeverity Minimum severity level to include
     * @return array<array<string, mixed>> Filtered findings
     */
    protected function filterBySeverity(array $findings, string $minSeverity): array
    {
        $severityLevels = [
            'low' => 1,
            'medium' => 2,
            'high' => 3,
            'critical' => 4
        ];

        $minLevel = $severityLevels[$minSeverity] ?? 1;

        return array_filter($findings, function ($finding) use ($severityLevels, $minLevel) {
            $findingSeverity = $finding['severity'] ?? 'low';
            $findingLevel = $severityLevels[$findingSeverity] ?? 1;
            return $findingLevel >= $minLevel;
        });
    }

    /**
     * Output results in the specified format.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     * @param string $format Output format (json|github|gitlab|jenkins)
     */
    protected function outputFormattedResults(array $findings, string $format): void
    {
        switch ($format) {
            case 'json':
                $this->outputJson($findings);
                break;
            case 'github':
                $this->outputGitHubActions($findings);
                break;
            case 'gitlab':
                $this->outputGitLabCI($findings);
                break;
            case 'jenkins':
                $this->outputJenkins($findings);
                break;
            default:
                $this->error('Unsupported output format: ' . $format);
                $this->info("Supported formats: json, github, gitlab, jenkins");
                break;
        }
    }

    /**
     * Output findings in JSON format.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     */
    protected function outputJson(array $findings): void
    {
        $output = [
            'warden_version' => $this->getWardenVersion(),
            'scan_date' => Carbon::now()->toISOString(),
            'vulnerabilities_found' => count($findings),
            'findings' => $findings
        ];

        $jsonOutput = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $this->output->writeln($jsonOutput);
    }

    /**
     * Output findings in GitHub Actions format.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     */
    protected function outputGitHubActions(array $findings): void
    {
        if ($findings === []) {
            $this->output->writeln('::notice title=Warden Security Audit::No security issues found.');
            return;
        }

        foreach ($findings as $finding) {
            $level = in_array($finding['severity'], ['critical', 'high']) ? 'error' : 'warning';
            $title = $finding['title'] ?? 'Security vulnerability';
            $package = $finding['package'] ?? 'unknown';

            $this->output->writeln(sprintf('::%s title=%s::%s - %s severity vulnerability found', $level, $title, $package, $finding['severity']));
        }
    }

    /**
     * Output findings in GitLab CI format.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     */
    protected function outputGitLabCI(array $findings): void
    {
        $vulnerabilities = [];

        foreach ($findings as $finding) {
            $vulnerabilities[] = [
                'id' => hash('sha256', serialize($finding)),
                'category' => 'dependency_scanning',
                'name' => $finding['title'] ?? 'Security vulnerability',
                'description' => $finding['description'] ?? $finding['title'] ?? 'Security vulnerability found',
                'severity' => strtoupper($finding['severity'] ?? 'Medium'),
                'scanner' => [
                    'id' => 'warden',
                    'name' => 'Warden'
                ],
                'location' => [
                    'file' => 'composer.json',
                    'dependency' => [
                        'package' => [
                            'name' => $finding['package'] ?? 'unknown'
                        ]
                    ]
                ]
            ];
        }

        $output = [
            'version' => '15.0.0',
            'vulnerabilities' => $vulnerabilities
        ];

        $jsonOutput = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $this->output->writeln($jsonOutput);
    }

    /**
     * Output findings in Jenkins format.
     *
     * @param array<array<string, mixed>> $findings List of vulnerability findings
     */
    protected function outputJenkins(array $findings): void
    {
        $output = [
            'warden_report' => [
                'timestamp' => Carbon::now()->toISOString(),
                'total_vulnerabilities' => count($findings),
                'vulnerabilities' => $findings
            ]
        ];

        $jsonOutput = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $this->output->writeln($jsonOutput);
    }

    /**
     * Get the current Warden version.
     */
    protected function getWardenVersion(): string
    {
        $composerPath = __DIR__ . '/../../composer.json';

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
}
