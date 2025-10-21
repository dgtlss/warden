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
use Dgtlss\Warden\Services\Audits\DockerAuditService;
use Dgtlss\Warden\Services\Audits\KubernetesAuditService;
use Dgtlss\Warden\Services\Audits\GitAuditService;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Notifications\Channels\SlackChannel;
use Dgtlss\Warden\Notifications\Channels\DiscordChannel;
use Dgtlss\Warden\Notifications\Channels\EmailChannel;
use Dgtlss\Warden\Notifications\Channels\TeamsChannel;
use Dgtlss\Warden\Contracts\CustomAudit;
use function Laravel\Prompts\info;
use function Laravel\Prompts\table;

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit 
    {--silent : Run the audit without sending notifications} 
    {--npm : Run the npm audit}
    {--docker : Run the docker audit}
    {--kubernetes : Run the kubernetes audit}
    {--git : Run the git audit}
    {--ignore-abandoned : Ignore abandoned packages, without throwing an error}
    {--output= : Output format (json|github|gitlab|jenkins)}
    {--severity= : Filter by severity level (low|medium|high|critical)}
    {--force : Force cache refresh and ignore cached results}';

    protected $description = 'Performs a composer audit and reports findings via Warden.';

    protected AuditCacheService $cacheService;
    protected ParallelAuditExecutor $parallelExecutor;

    public function __construct(AuditCacheService $cacheService, ParallelAuditExecutor $parallelExecutor)
    {
        parent::__construct();
        $this->cacheService = $cacheService;
        $this->parallelExecutor = $parallelExecutor;
    }

    /**
     * Execute the console command.
     *
     * @return int Exit code: 0 for success, 1 for vulnerabilities found, 2 for audit failures
     */
    public function handle(): int
    {
        $this->displayVersion();
        
        // Handle cache clearing if force option is used
        if ($this->option('force')) {
            $this->cacheService->clearCache();
            $this->info('Cache cleared.');
        }

        // Check if we should use parallel execution
        $useParallel = config('warden.audits.parallel_execution', true);
        
        if ($useParallel) {
            return $this->runParallelAudits();
        } else {
            return $this->runSequentialAudits();
        }
    }

    protected function runParallelAudits(): int
    {
        $auditServices = $this->initializeAuditServices();
        
        // Add services to parallel executor
        foreach ($auditServices as $service) {
            $this->parallelExecutor->addAudit($service);
        }

        $this->info('Running security audits in parallel...');
        $results = $this->parallelExecutor->execute(true);
        
        // Collect findings and abandoned packages
        $allFindings = [];
        $abandonedPackages = [];
        $hasFailures = false;

        foreach ($results as $name => $result) {
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

    protected function runSequentialAudits(): int
    {
        $auditServices = $this->initializeAuditServices();
        $hasFailures = false;
        $allFindings = [];
        $abandonedPackages = [];

        foreach ($auditServices as $service) {
            $auditName = $service->getName();
            
            // Check cache first (unless force is used)
            if (!$this->option('force') && $this->cacheService->hasRecentAudit($auditName)) {
                $this->info("Using cached results for {$auditName} audit...");
                $cached = $this->cacheService->getCachedResult($auditName);
                if (!empty($cached['result'])) {
                    $allFindings = array_merge($allFindings, $cached['result']);
                }
                continue;
            }

            $this->info("Running {$auditName} audit...");
            
            if (!$service->run()) {
                $this->handleAuditFailure($service);
                $hasFailures = true;
                continue;
            }

            $findings = $service->getFindings();
            if (!empty($findings)) {
                $allFindings = array_merge($allFindings, $findings);
                // Cache the results
                $this->cacheService->storeResult($auditName, $findings);
            }

            // Collect abandoned packages
            if ($service instanceof ComposerAuditService) {
                $abandonedPackages = $service->getAbandonedPackages();
            }
        }

        return $this->processResults($allFindings, $abandonedPackages, $hasFailures);
    }

    protected function processResults(array $allFindings, array $abandonedPackages, bool $hasFailures): int
    {
        // Apply severity filtering if specified
        if ($this->option('severity')) {
            $allFindings = $this->filterBySeverity($allFindings, $this->option('severity'));
        }

        // Handle abandoned packages
        $this->handleAbandonedPackages($abandonedPackages);

        // Handle output formatting
        $outputFormat = $this->option('output');
        if ($outputFormat) {
            $this->outputFormattedResults($allFindings, $outputFormat);
            return !empty($allFindings) ? 1 : ($hasFailures ? 2 : 0);
        }

        // Display and handle findings (default console output)
        if (!empty($allFindings)) {
            $this->displayFindings($allFindings);
            
            if (!$this->option('silent')) {
                $this->sendNotifications($allFindings);
                $this->newLine();
                info('Notifications sent.');
            }

            return 1;
        }

        info('No vulnerabilities found.');
        return $hasFailures ? 2 : 0;
    }

    /**
     * Display the current version of Warden.
     *
     * @return void
     */
    protected function displayVersion(): void
    {
        $composerJson = json_decode(file_get_contents(__DIR__ . '/../../composer.json'), true);
        $this->info('Warden Audit Version ' . ($composerJson['version'] ?? 'unknown'));
    }

    /**
     * Initialize and return all audit services based on command options.
     *
     * @return array Array of audit service instances
     */
    protected function initializeAuditServices(): array
    {
        $services = [
            new ComposerAuditService(),
            new EnvAuditService(),
            new StorageAuditService(),
            new DebugModeAuditService(),
        ];

        if ($this->option('npm')) {
            $services[] = new NpmAuditService();
        }

        if ($this->option('docker')) {
            $services[] = new DockerAuditService();
        }

        if ($this->option('kubernetes')) {
            $services[] = new KubernetesAuditService();
        }

        if ($this->option('git')) {
            $services[] = new GitAuditService();
        }

        // Load custom audits from configuration
        $customAudits = config('warden.custom_audits', []);
        foreach ($customAudits as $customAuditClass) {
            if (class_exists($customAuditClass)) {
                try {
                    $customAudit = app()->make($customAuditClass);
                    if (method_exists($customAudit, 'shouldRun') && !$customAudit->shouldRun()) {
                        continue;
                    }
                    $services[] = new CustomAuditWrapper($customAudit);
                    $this->info("Loaded custom audit: {$customAudit->getName()}");
                } catch (\Exception $e) {
                    $this->warn("Failed to load custom audit {$customAuditClass}: {$e->getMessage()}");
                }
            } else {
                $this->warn("Custom audit class not found: {$customAuditClass}");
            }
        }
        
        return $services;
    }

    /**
     * Handle a failed audit service.
     *
     * @param object $service The audit service that failed
     * @return void
     */
    protected function handleAuditFailure(object $service): void
    {
        $this->error("{$service->getName()} audit failed to run.");
        if ($service instanceof ComposerAuditService) {
            $this->error("Error: " . Collection::make($service->getFindings())->last()['error'] ?? 'Unknown error');
        }
    }

    /**
     * Process and display abandoned packages information.
     *
     * @param array $abandonedPackages List of abandoned packages
     * @return void
     */
    protected function handleAbandonedPackages(array $abandonedPackages): void
    {
        if (empty($abandonedPackages)) {
            return;
        }
        
        if ($this->option('ignore-abandoned')) {
            $this->warn(count($abandonedPackages) . ' abandoned packages found (ignored due to --ignore-abandoned flag)');
            return;
        }
        
        $this->warn(count($abandonedPackages) . ' abandoned packages found.');
        
        $headers = ['Package', 'Recommended Replacement'];
        $rows = [];

        foreach ($abandonedPackages as $package) {
            $rows[] = [
                $package['package'],
                $package['replacement'] ?? 'No replacement suggested'
            ];
        }

        table(
            headers: $headers,
            rows: $rows
        );

        if (!$this->option('silent')) {
            $this->sendAbandonedPackagesNotification($abandonedPackages);
        }
    }

    /**
     * Display audit findings in a formatted table.
     *
     * @param array $findings List of vulnerability findings
     * @return void
     */
    protected function displayFindings(array $findings): void
    {
        $this->error(count($findings) . ' vulnerabilities found.');
        
        $headers = ['Source', 'Package', 'Title', 'Severity', 'CVE', 'Link', 'Affected Versions'];
        $rows = [];

        foreach ($findings as $finding) {
            $rows[] = [
                $finding['source'],
                $finding['package'],
                $finding['title'],
                $finding['severity'],
                $finding['cve'] ?? '-',
                $finding['cve'] ? 'https://www.cve.org/CVERecord?id=' . $finding['cve'] : '-',
                $finding['affected_versions'] ?? '-'
            ];
        }

        table(
            headers: $headers,
            rows: $rows
        );
    }

    /**
     * Prepare a structured report from advisory data.
     *
     * @param array $advisories Advisory data organized by package
     * @return array Structured report data
     */
    protected function prepareReport(array $advisories): array
    {
        $report = "Warden Audit Report\n\n";
        $reportData = [];
        foreach ($advisories as $package => $issues) {
            $packageIssues = [];
            foreach ($issues as $issue) {
                $packageIssues[] = [
                    'title' => $issue['title'],
                    'cve' => $issue['cve'],
                    'link' => "https://www.cve.org/CVERecord?id={$issue['cve']}",
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
     * @param array $findings List of vulnerability findings
     * @return void
     */
    protected function sendNotifications(array $findings): void
    {
        $channels = $this->getNotificationChannels();

        foreach ($channels as $channel) {
            try {
                $channel->send($findings);
                $this->info("Notification sent via {$channel->getName()}");
            } catch (\Exception $e) {
                $this->warn("Failed to send notification via {$channel->getName()}: {$e->getMessage()}");
            }
        }

        // Legacy support
        $this->sendLegacyNotifications($findings);
    }

    /**
     * Get configured notification channels.
     *
     * @return array
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
     * @param array $findings List of vulnerability findings
     * @return void
     */
    protected function sendLegacyNotifications(array $findings): void
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        if ($webhookUrl) {
            $this->sendWebhookNotification($webhookUrl, $findings);
        }

        if ($emailRecipients) {
            $recipients = is_string($emailRecipients) ? explode(',', $emailRecipients) : $emailRecipients;
            $this->sendEmailReport($findings, $recipients);
        }
    }

    /**
     * Send a webhook notification with audit findings.
     *
     * @param string $webhookUrl The URL to send the webhook to
     * @param array $findings List of vulnerability findings
     * @return void
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
     * @param array $findings List of vulnerability findings
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
                $message .= "  CVE: {$finding['cve']} - https://www.cve.org/CVERecord?id={$finding['cve']}\n";
            }
            $message .= "\n";
        }
        
        return $message;
    }

    /**
     * Send an email report with audit findings.
     *
     * @param array $report Report data to include in the email
     * @param array $emailRecipients Recipients of the email
     * @return void
     */
    protected function sendEmailReport(array $report, array $emailRecipients): void
    {
        Mail::send('warden::mail.report', ['report' => $report], function ($message) use ($emailRecipients, $report) {
            $message->to($emailRecipients)
                    ->subject('Warden Audit Report');
        });
    }

    /**
     * Send notifications about abandoned packages.
     *
     * @param array $abandonedPackages List of abandoned packages
     * @return void
     */
    protected function sendAbandonedPackagesNotification(array $abandonedPackages): void
    {
        $channels = $this->getNotificationChannels();

        foreach ($channels as $channel) {
            try {
                if (method_exists($channel, 'sendAbandonedPackages')) {
                    $channel->sendAbandonedPackages($abandonedPackages);
                    $this->info("Abandoned packages notification sent via {$channel->getName()}");
                }
            } catch (\Exception $e) {
                $this->warn("Failed to send abandoned packages notification via {$channel->getName()}: {$e->getMessage()}");
            }
        }

        // Legacy support
        $this->sendLegacyAbandonedPackagesNotification($abandonedPackages);
    }

    /**
     * Send legacy notifications for abandoned packages.
     *
     * @param array $abandonedPackages List of abandoned packages
     * @return void
     */
    protected function sendLegacyAbandonedPackagesNotification(array $abandonedPackages): void
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        $message = "The following packages are marked as abandoned:\n\n";
        foreach ($abandonedPackages as $package) {
            $message .= "- {$package['package']}";
            if ($package['replacement']) {
                $message .= " (Recommended replacement: {$package['replacement']})";
            }
            $message .= "\n";
        }

        if ($webhookUrl) {
            Http::post($webhookUrl, ['text' => $message]);
        }

        if ($emailRecipients) {
            $recipients = is_string($emailRecipients) ? explode(',', $emailRecipients) : $emailRecipients;
            Mail::raw($message, function ($message) use ($recipients) {
                $message->to($recipients)
                        ->subject('Warden Audit - Abandoned Packages Found');
            });
        }
    }

    /**
     * Filter findings by severity level.
     *
     * @param array $findings List of vulnerability findings
     * @param string $minSeverity Minimum severity level to include
     * @return array Filtered findings
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
     * @param array $findings List of vulnerability findings
     * @param string $format Output format (json|github|gitlab|jenkins)
     * @return void
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
                $this->error("Unsupported output format: {$format}");
                $this->info("Supported formats: json, github, gitlab, jenkins");
                break;
        }
    }

    /**
     * Output findings in JSON format.
     *
     * @param array $findings List of vulnerability findings
     * @return void
     */
    protected function outputJson(array $findings): void
    {
        $output = [
            'warden_version' => $this->getWardenVersion(),
            'scan_date' => Carbon::now()->toISOString(),
            'vulnerabilities_found' => count($findings),
            'findings' => $findings
        ];

        $this->output->writeln(json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * Output findings in GitHub Actions format.
     *
     * @param array $findings List of vulnerability findings
     * @return void
     */
    protected function outputGitHubActions(array $findings): void
    {
        foreach ($findings as $finding) {
            $level = in_array($finding['severity'], ['critical', 'high']) ? 'error' : 'warning';
            $title = $finding['title'] ?? 'Security vulnerability';
            $package = $finding['package'] ?? 'unknown';
            
            $this->output->writeln("::$level title=$title::$package - {$finding['severity']} severity vulnerability found");
        }
    }

    /**
     * Output findings in GitLab CI format.
     *
     * @param array $findings List of vulnerability findings
     * @return void
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

        $this->output->writeln(json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * Output findings in Jenkins format.
     *
     * @param array $findings List of vulnerability findings
     * @return void
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

        $this->output->writeln(json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * Get the current Warden version.
     *
     * @return string
     */
    protected function getWardenVersion(): string
    {
        $composerJson = json_decode(file_get_contents(__DIR__ . '/../../composer.json'), true);
        return $composerJson['version'] ?? 'unknown';
    }
}

/**
 * Wrapper class to adapt CustomAudit interface to AbstractAuditService pattern.
 */
class CustomAuditWrapper
{
    protected CustomAudit $customAudit;
    protected array $findings = [];

    public function __construct(CustomAudit $customAudit)
    {
        $this->customAudit = $customAudit;
    }

    public function getName(): string
    {
        return $this->customAudit->getName();
    }

    public function run(): bool
    {
        $success = $this->customAudit->audit();
        
        if (!$success) {
            $this->findings = $this->customAudit->getFindings();
        }
        
        return $success;
    }

    public function getFindings(): array
    {
        return $this->findings;
    }

    public function shouldRun(): bool
    {
        return method_exists($this->customAudit, 'shouldRun') ? $this->customAudit->shouldRun() : true;
    }
}
