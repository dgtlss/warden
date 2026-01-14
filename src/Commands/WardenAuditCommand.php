<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Collection;
use Carbon\Carbon;
use Symfony\Component\Process\Process;
use Dgtlss\Warden\Jobs\RunSecurityAuditJob;
use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Services\Audits\EnvAuditService;
use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\AuditRateLimiter;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Notifications\Channels\SlackChannel;
use Dgtlss\Warden\Notifications\Channels\DiscordChannel;
use Dgtlss\Warden\Notifications\Channels\EmailChannel;
use Dgtlss\Warden\Notifications\Channels\TeamsChannel;
use Dgtlss\Warden\Contracts\CustomAudit;
use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\ValueObjects\Finding;
use function Laravel\Prompts\info;
use function Laravel\Prompts\note;
use function Laravel\Prompts\warning;
use function Laravel\Prompts\error;
use function Laravel\Prompts\table;
use function Laravel\Prompts\confirm;
use function Laravel\Prompts\select;
use function Laravel\Prompts\multiselect;
use function Laravel\Prompts\progress;

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit 
    {--silent : Run the audit without sending notifications} 
    {--npm : Run the npm audit}
    {--ignore-abandoned : Ignore abandoned packages, without throwing an error}
    {--output= : Output format (json|github|gitlab|jenkins)}
    {--severity= : Filter by severity level (low|medium|high|critical)}
    {--force : Force cache refresh and ignore cached results}
    {--queue : Run the audit as a background job}
    {--dry-run : Simulate audit without sending notifications}
    {--interactive : Run in interactive mode with prompts}';

    protected $description = 'Performs a composer audit and reports findings via Warden.';

    protected AuditCacheService $cacheService;

    protected ParallelAuditExecutor $parallelExecutor;

    public function __construct(AuditCacheService $auditCacheService, ParallelAuditExecutor $parallelAuditExecutor)
    {
        parent::__construct();
        $this->cacheService = $auditCacheService;
        $this->parallelExecutor = $parallelAuditExecutor;
    }

    /**
     * Execute the console command.
     *
     * @return int Exit code: 0 for success, 1 for vulnerabilities found, 2 for audit failures
     */
    public function handle(): int
    {
        $this->displayVersion();

        if ($this->option('dry-run')) {
            note('DRY RUN MODE: Notifications will be simulated but not sent.');
        }

        if (!$this->checkRateLimit()) {
            return 2;
        }

        if ($this->option('interactive')) {
            return $this->runInteractiveMode();
        }

        if ($this->option('queue')) {
            return $this->dispatchQueuedAudit();
        }

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

    /**
     * Run the audit in interactive mode using Laravel Prompts.
     */
    protected function runInteractiveMode(): int
    {
        note('Welcome to Warden Interactive Mode!');

        /** @var array<string> $audits */
        $audits = multiselect(
            label: 'Which audits do you want to run?',
            options: [
                'composer' => 'Composer Dependencies',
                'npm' => 'NPM Packages',
                'env' => 'Environment Configuration',
                'storage' => 'Storage Permissions',
                'debug' => 'Debug Mode Detection',
            ],
            default: ['composer', 'env', 'storage', 'debug'],
            required: true,
        );

        /** @var string $severity */
        $severity = select(
            label: 'Minimum severity level to report?',
            options: [
                'low' => 'Low (show all)',
                'medium' => 'Medium and above',
                'high' => 'High and above',
                'critical' => 'Critical only',
            ],
            default: 'low',
        );

        $notify = confirm(
            label: 'Send notifications when vulnerabilities are found?',
            default: true,
        );

        $forceRefresh = confirm(
            label: 'Force cache refresh?',
            default: false,
        );

        if ($forceRefresh) {
            $this->cacheService->clearCache();
            note('Cache cleared.');
        }

        $includeNpm = in_array('npm', $audits, true);
        $this->input->setOption('npm', $includeNpm);
        $this->input->setOption('silent', !$notify);
        $this->input->setOption('severity', $severity !== 'low' ? $severity : null);

        $useParallel = config('warden.audits.parallel_execution', true);

        if ($useParallel) {
            return $this->runParallelAudits();
        }

        return $this->runSequentialAudits();
    }

    /**
     * Check if the audit is rate limited.
     */
    protected function checkRateLimit(): bool
    {
        $rateLimiter = AuditRateLimiter::fromConfig();

        if (!$rateLimiter->isEnabled()) {
            return true;
        }

        $key = $rateLimiter->getContextKey();

        if ($rateLimiter->tooManyAttempts($key)) {
            $secondsUntilAvailable = $rateLimiter->availableIn($key);
            $this->error("Rate limit exceeded. Please wait {$secondsUntilAvailable} seconds before trying again.");

            return false;
        }

        $rateLimiter->hit($key);

        return true;
    }

    /**
     * Dispatch the audit as a queued job.
     */
    protected function dispatchQueuedAudit(): int
    {
        $auditTypes = ['composer', 'env', 'storage', 'debug'];

        if ($this->option('npm')) {
            $auditTypes[] = 'npm';
        }

        $severity = $this->option('severity');
        $notify = !$this->option('silent');
        $forceRefresh = (bool) $this->option('force');

        $job = new RunSecurityAuditJob(
            auditTypes: $auditTypes,
            severity: is_string($severity) ? $severity : null,
            notify: $notify,
            forceRefresh: $forceRefresh,
        );

        /** @var string|null $connection */
        $connection = config('warden.queue.connection');

        /** @var string $queueName */
        $queueName = config('warden.queue.queue_name', 'default');

        if ($connection !== null) {
            $job->onConnection($connection);
        }

        $job->onQueue($queueName);

        dispatch($job);

        $this->info('Security audit has been queued for background processing.');

        return 0;
    }

    protected function runParallelAudits(): int
    {
        $auditServices = $this->initializeAuditServices();

        $this->verboseOutput('Initializing ' . count($auditServices) . ' audit service(s) for parallel execution...');

        // Add services to parallel executor
        foreach ($auditServices as $auditService) {
            $this->parallelExecutor->addAudit($auditService);
            $this->verboseOutput('Added ' . $auditService->getName() . ' audit to parallel executor');
        }

        $startTime = microtime(true);
        note('Running ' . count($auditServices) . ' security audits in parallel...');
        $results = $this->parallelExecutor->execute(true);
        $duration = round((microtime(true) - $startTime) * 1000, 2);
        $this->verboseOutput("Parallel execution completed in {$duration}ms");

        // Collect findings and abandoned packages
        /** @var array<int, Finding> $allFindings */
        $allFindings = [];
        $abandonedPackages = [];
        $hasFailures = false;

        /** @var array<int, array{success: bool, service: object, findings?: array<int, Finding>}> $typedResults */
        $typedResults = $results;

        if ($typedResults === []) {
            return $this->processResults($allFindings, $abandonedPackages, $hasFailures);
        }

        /** @var array<int, array{success: bool, service: object, findings?: array<int, Finding>}> $processedResults */
        $processedResults = progress(
            label: 'Processing audit results',
            steps: $typedResults,
            callback: fn (array $result) => $result,
            hint: 'Collecting findings...',
        );

        foreach ($processedResults as $result) {
            /** @var object $service */
            $service = $result['service'];
            $serviceNameRaw = method_exists($service, 'getName') ? $service->getName() : null;
            $serviceName = is_string($serviceNameRaw) ? $serviceNameRaw : 'unknown';

            if (!$result['success']) {
                $this->handleAuditFailure($service);
                $hasFailures = true;
                $this->verboseOutput('Audit failed: ' . $serviceName);
                continue;
            }

            if (!empty($result['findings'])) {
                /** @var array<int, Finding> $findings */
                $findings = $result['findings'];
                $allFindings = array_merge($allFindings, $findings);
                $this->verboseOutput('Found ' . count($findings) . ' issue(s) from ' . $serviceName);
            }

            // Collect abandoned packages from composer audit
            if ($service instanceof ComposerAuditService) {
                $abandonedPackages = $service->getAbandonedPackages();
                $this->verboseOutput('Found ' . count($abandonedPackages) . ' abandoned package(s)');
            }
        }

        return $this->processResults($allFindings, $abandonedPackages, $hasFailures);
    }

    protected function runSequentialAudits(): int
    {
        $auditServices = $this->initializeAuditServices();
        $hasFailures = false;
        /** @var array<int, Finding> $allFindings */
        $allFindings = [];
        $abandonedPackages = [];

        $this->verboseOutput('Initializing ' . count($auditServices) . ' audit service(s)...');

        /** @var array<int, array{findings: array<int, Finding>, abandoned: array<int, array<string, mixed>>, failed: bool, service?: \Dgtlss\Warden\Contracts\AuditService}> $results */
        $results = progress(
            label: 'Running security audits',
            steps: $auditServices,
            callback: function (\Dgtlss\Warden\Contracts\AuditService $auditService) {
                $auditName = $auditService->getName();
                $startTime = microtime(true);

                $this->verboseOutput("Starting {$auditName} audit...");

                // Check cache first (unless force is used)
                if (!$this->option('force') && $this->cacheService->hasRecentAudit($auditName)) {
                    $this->verboseOutput("Cache hit for {$auditName} audit");
                    $cached = $this->cacheService->getCachedResult($auditName);
                    /** @var array<int, Finding> $cachedFindings */
                    $cachedFindings = [];
                    if ($cached !== null && !empty($cached['result'])) {
                        foreach ($cached['result'] as $findingData) {
                            $cachedFindings[] = Finding::fromArray($findingData);
                        }
                    }

                    return ['findings' => $cachedFindings, 'abandoned' => [], 'failed' => false];
                }

                $this->verboseOutput("Cache miss for {$auditName} - running fresh audit");

                if (!$auditService->run()) {
                    $duration = round((microtime(true) - $startTime) * 1000, 2);
                    $this->verboseOutput("{$auditName} audit failed after {$duration}ms");

                    return ['findings' => [], 'abandoned' => [], 'failed' => true, 'service' => $auditService];
                }

                $findings = $auditService->getFindings();
                $duration = round((microtime(true) - $startTime) * 1000, 2);
                $this->verboseOutput("{$auditName} audit completed in {$duration}ms - found " . count($findings) . " issue(s)");

                if (!empty($findings)) {
                    $this->cacheService->storeResult($auditName, array_map(fn(Finding $f) => $f->toArray(), $findings));
                }

                /** @var array<int, array<string, mixed>> $abandoned */
                $abandoned = [];
                if ($auditService instanceof ComposerAuditService) {
                    $abandoned = $auditService->getAbandonedPackages();
                }

                return ['findings' => $findings, 'abandoned' => $abandoned, 'failed' => false];
            },
            hint: 'Checking for security vulnerabilities...',
        );

        foreach ($results as $result) {
            if ($result['failed']) {
                if (array_key_exists('service', $result)) {
                    $this->handleAuditFailure($result['service']);
                }

                $hasFailures = true;
                continue;
            }

            if (!empty($result['findings'])) {
                $allFindings = array_merge($allFindings, $result['findings']);
            }

            if (!empty($result['abandoned'])) {
                $abandonedPackages = array_merge($abandonedPackages, $result['abandoned']);
            }
        }

        return $this->processResults($allFindings, $abandonedPackages, $hasFailures);
    }

    /**
     * Process and display audit results.
     *
     * @param array<int, Finding> $allFindings
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    protected function processResults(array $allFindings, array $abandonedPackages, bool $hasFailures): int
    {
        // Apply severity filtering if specified
        if ($this->option('severity')) {
            $severityOption = $this->option('severity');
            if (is_string($severityOption)) {
                $allFindings = $this->filterBySeverity($allFindings, $severityOption);
            }
        }

        // Handle abandoned packages
        $this->handleAbandonedPackages($abandonedPackages);

        // Handle output formatting
        $outputFormat = $this->option('output');
        if (is_string($outputFormat) && $outputFormat !== '') {
            $this->outputFormattedResults($allFindings, $outputFormat);
            return $allFindings === [] ? ($hasFailures ? 2 : 0) : (1);
        }

        // Display and handle findings (default console output)
        if ($allFindings !== []) {
            $this->displayFindings($allFindings);

            if (!$this->option('silent') && !$this->option('dry-run')) {
                $this->sendNotifications($allFindings);
                $this->newLine();
                info('Notifications sent.');
            } elseif ($this->option('dry-run')) {
                $this->newLine();
                $channelCount = count($this->getNotificationChannels());
                note(sprintf('DRY RUN: Would have sent %d notifications via %d configured channel(s).', count($allFindings), $channelCount));
            }

            return 1;
        }

        info('No vulnerabilities found.');
        return $hasFailures ? 2 : 0;
    }

    /**
     * Display the current version of Warden.
     */
    protected function displayVersion(): void
    {
        $this->info('Warden Audit Version ' . $this->getWardenVersion());
    }

    /**
     * Output verbose debugging information if verbose mode is enabled.
     */
    protected function verboseOutput(string $message): void
    {
        if ($this->output->isVerbose()) {
            $timestamp = date('H:i:s');
            $this->line("<comment>[{$timestamp}]</comment> {$message}");
        }
    }

    /**
     * Initialize and return all audit services based on command options.
     *
     * @return array<int, \Dgtlss\Warden\Contracts\AuditService> Array of audit service instances
     */
    protected function initializeAuditServices(): array
    {
        /** @var array<int, \Dgtlss\Warden\Contracts\AuditService> $services */
        $services = [
            new ComposerAuditService(),
            new EnvAuditService(),
            new StorageAuditService(),
            new DebugModeAuditService(),
        ];

        if ($this->option('npm')) {
            $services[] = new NpmAuditService();
        }

        // Load custom audits from configuration
        $customAudits = config('warden.custom_audits', []);
        if (is_iterable($customAudits)) {
            foreach ($customAudits as $customAuditClass) {
                if (!is_string($customAuditClass) || !class_exists($customAuditClass)) {
                    if (is_string($customAuditClass)) {
                        $this->warn('Custom audit class not found: ' . $customAuditClass);
                    }
                    continue;
                }

                try {
                    /** @var object $customAudit */
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
        $serviceName = 'Unknown service';
        if (method_exists($service, 'getName')) {
            $name = $service->getName();
            $serviceName = is_string($name) ? $name : 'Unknown service';
        }
        $this->error($serviceName . ' audit failed to run.');
        if ($service instanceof ComposerAuditService) {
            $findings = $service->getFindings();
            $lastFinding = Collection::make($findings)->last();
            $error = $lastFinding instanceof Finding ? $lastFinding->error : 'Unknown error';
            $this->error("Error: " . (is_string($error) ? $error : 'Unknown error'));
        }
    }

    /**
     * Process and display abandoned packages information.
     *
     * @param array<int, array<string, mixed>> $abandonedPackages List of abandoned packages
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
        /** @var array<int, array<int, string>> $rows */
        $rows = [];

        foreach ($abandonedPackages as $abandonedPackage) {
            $rows[] = [
                is_string($abandonedPackage['package'] ?? null) ? $abandonedPackage['package'] : 'unknown',
                is_string($abandonedPackage['replacement'] ?? null) ? $abandonedPackage['replacement'] : 'No replacement suggested'
            ];
        }

        table(
            headers: $headers,
            rows: $rows
        );

        if (!$this->option('silent') && !$this->option('dry-run')) {
            /** @var array<int, array<string, mixed>> $abandonedPackagesTyped */
            $abandonedPackagesTyped = $abandonedPackages;
            $this->sendAbandonedPackagesNotification($abandonedPackagesTyped);
        } elseif ($this->option('dry-run')) {
            note(sprintf('DRY RUN: Would have sent abandoned packages notification for %d packages.', count($abandonedPackages)));
        }
    }

    /**
     * Display audit findings in a formatted table.
     *
     * @param array<int, Finding> $findings List of vulnerability findings
     */
    protected function displayFindings(array $findings): void
    {
        $this->error(count($findings) . ' vulnerabilities found.');

        $headers = ['Source', 'Package', 'Title', 'Severity', 'CVE', 'Link', 'Affected Versions'];
        /** @var array<int, array<int, string>> $rows */
        $rows = [];

        foreach ($findings as $finding) {
            /** @var string|null $cve */
            $cve = $finding->cve;
            $rows[] = [
                $finding->source,
                $finding->package,
                $finding->title,
                $finding->severity->value,
                $cve ?? '-',
                is_string($cve) ? sprintf('https://www.cve.org/CVERecord?id=%s', $cve) : '-',
                $finding->affectedVersions ?? '-'
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
     * @param array<string, array<array<string, mixed>>> $advisories Advisory data organized by package
     * @return array<string, array<array<string, mixed>>> Structured report data
     */
    protected function prepareReport(array $advisories): array
    {
        $reportData = [];
        foreach ($advisories as $package => $issues) {
            $packageIssues = [];
            foreach ($issues as $issue) {
                $cve = isset($issue['cve']) && is_string($issue['cve']) ? $issue['cve'] : 'N/A';
                $title = isset($issue['title']) && is_string($issue['title']) ? $issue['title'] : 'Unknown';
                $affectedVersions = isset($issue['affected_versions']) && is_string($issue['affected_versions']) ? $issue['affected_versions'] : 'Any';
                
                $packageIssues[] = [
                    'title' => $title,
                    'cve' => $cve,
                    'link' => 'https://www.cve.org/CVERecord?id=' . $cve,
                    'affected_versions' => $affectedVersions
                ];
            }

            $reportData[$package] = $packageIssues;
        }

        return $reportData;
    }

    /**
     * Send notifications about vulnerabilities through configured channels.
     *
     * @param array<int, Finding> $findings List of vulnerability findings
     */
    protected function sendNotifications(array $findings): void
    {
        $channels = $this->getNotificationChannels();

        foreach ($channels as $channel) {
            try {
                $channel->send($findings);
                $this->info('Notification sent via ' . $channel->getName());
            } catch (\Exception $e) {
                $this->warn(sprintf('Failed to send notification via %s: %s', $channel->getName(), $e->getMessage()));
            }
        }

        // Legacy support
        $this->sendLegacyNotifications($findings);
    }

    /**
     * Get configured notification channels.
     *
     * @return array<int, NotificationChannel>
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
     * @param array<int, Finding> $findings List of vulnerability findings
     */
    protected function sendLegacyNotifications(array $findings): void
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        if ($webhookUrl && is_string($webhookUrl)) {
            $this->sendWebhookNotification($webhookUrl, $findings);
        }

        if ($emailRecipients) {
            /** @var array<string> $recipients */
            $recipients = is_string($emailRecipients) ? explode(',', $emailRecipients) : (is_array($emailRecipients) ? $emailRecipients : []);
            if ($recipients !== []) {
                $this->sendEmailReport($findings, $recipients);
            }
        }
    }

    /**
     * Send a webhook notification with audit findings.
     *
     * @param string $webhookUrl The URL to send webhook to
     * @param array<int, Finding> $findings List of vulnerability findings
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
     * @param array<int, Finding> $findings List of vulnerability findings
     * @return string Formatted message
     */
    protected function formatFindingsForWebhook(array $findings): string
    {
        // Implement a better formatting for webhook notifications
        $message = "🚨 *Warden Security Audit Report* 🚨\n\n";
        $message .= count($findings) . " vulnerabilities found:\n\n";

        foreach ($findings as $finding) {
            $message .= "• *{$finding->package}*: {$finding->title} ({$finding->severity->value})\n";
            if (!empty($finding->cve)) {
                $message .= sprintf('  CVE: %s - https://www.cve.org/CVERecord?id=%s%s', $finding->cve, $finding->cve, PHP_EOL);
            }

            $message .= "\n";
        }

        return $message;
    }

    /**
     * Send an email report with audit findings.
     *
     * @param array<int, Finding> $report Report data to include in email
     * @param array<string> $emailRecipients Recipients of email
     */
    protected function sendEmailReport(array $report, array $emailRecipients): void
    {
        Mail::send('warden::mail.report', ['report' => $report], function ($message) use ($emailRecipients): void {
            /** @var \Illuminate\Mail\Message $message */
            $message->to($emailRecipients)
                    ->subject('Warden Audit Report');
        });
    }

    /**
     * Send notifications about abandoned packages.
     *
     * @param array<int, array<string, mixed>> $abandonedPackages List of abandoned packages
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
        /** @var array<int, array<string, mixed>> $abandonedPackagesTyped */
        $abandonedPackagesTyped = $abandonedPackages;
        $this->sendLegacyAbandonedPackagesNotification($abandonedPackagesTyped);
    }

    /**
     * Send legacy notifications for abandoned packages.
     *
     * @param array<int, array<string, mixed>> $abandonedPackages List of abandoned packages
     */
    protected function sendLegacyAbandonedPackagesNotification(array $abandonedPackages): void
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        $message = "The following packages are marked as abandoned:\n\n";
        foreach ($abandonedPackages as $abandonedPackage) {
            $packageName = is_string($abandonedPackage['package'] ?? null) ? $abandonedPackage['package'] : 'unknown';
            $message .= '- ' . $packageName;
            if (isset($abandonedPackage['replacement']) && is_string($abandonedPackage['replacement'])) {
                $message .= sprintf(' (Recommended replacement: %s)', $abandonedPackage['replacement']);
            }

            $message .= "\n";
        }

        if ($webhookUrl && is_string($webhookUrl)) {
            Http::post($webhookUrl, ['text' => $message]);
        }

        if ($emailRecipients) {
            /** @var array<string> $recipients */
            $recipients = is_string($emailRecipients) ? explode(',', $emailRecipients) : (is_array($emailRecipients) ? $emailRecipients : []);
            if ($recipients !== []) {
                Mail::raw($message, function ($message) use ($recipients): void {
                    /** @var \Illuminate\Mail\Message $message */
                    $message->to($recipients)
                            ->subject('Warden Audit - Abandoned Packages Found');
                });
            }
        }
    }

    /**
     * Filter findings by severity level.
     *
     * @param array<int, Finding> $findings List of vulnerability findings
     * @param string $minSeverity Minimum severity level to include
     * @return array<int, Finding> Filtered findings
     */
    protected function filterBySeverity(array $findings, string $minSeverity): array
    {
        $severityLevels = [
            'low' => 1,
            'medium' => 2,
            'moderate' => 2,
            'high' => 3,
            'critical' => 4
        ];

        $minLevel = $severityLevels[$minSeverity] ?? 1;

        return array_filter($findings, function (Finding $finding) use ($severityLevels, $minLevel) {
            $findingLevel = $severityLevels[$finding->severity->value] ?? 1;
            return $findingLevel >= $minLevel;
        });
    }

    /**
     * Output results in the specified format.
     *
     * @param array<int, Finding> $findings List of vulnerability findings
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
     * @param array<int, Finding> $findings List of vulnerability findings
     */
    protected function outputJson(array $findings): void
    {
        $output = [
            'warden_version' => $this->getWardenVersion(),
            'scan_date' => Carbon::now()->toISOString(),
            'vulnerabilities_found' => count($findings),
            'findings' => array_map(fn(Finding $f) => $f->toArray(), $findings)
        ];

        $jsonOutput = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($jsonOutput !== false) {
            $this->output->writeln($jsonOutput);
        }
    }

    /**
     * Output findings in GitHub Actions format.
     *
     * @param array<int, Finding> $findings List of vulnerability findings
     */
    protected function outputGitHubActions(array $findings): void
    {
        foreach ($findings as $finding) {
            $level = $finding->severity->toGitHubLevel();
            $title = $finding->title;
            $package = $finding->package;

            $this->output->writeln(sprintf('::%s title=%s::%s - %s severity vulnerability found', $level, $title, $package, $finding->severity->value));
        }
    }

    /**
     * Output findings in GitLab CI format.
     *
     * @param array<int, Finding> $findings List of vulnerability findings
     */
    protected function outputGitLabCI(array $findings): void
    {
        $vulnerabilities = [];

        foreach ($findings as $finding) {
            $vulnerabilities[] = [
                'id' => hash('sha256', serialize($finding)),
                'category' => 'dependency_scanning',
                'name' => $finding->title,
                'description' => $finding->title . ' security vulnerability found',
                'severity' => strtoupper($finding->severity->value),
                'scanner' => [
                    'id' => 'warden',
                    'name' => 'Warden'
                ],
                'location' => [
                    'file' => 'composer.json',
                    'dependency' => [
                        'package' => [
                            'name' => $finding->package
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
        if ($jsonOutput !== false) {
            $this->output->writeln($jsonOutput);
        }
    }

    /**
     * Output findings in Jenkins format.
     *
     * @param array<int, Finding> $findings List of vulnerability findings
     */
    protected function outputJenkins(array $findings): void
    {
        $output = [
            'warden_report' => [
                'timestamp' => Carbon::now()->toISOString(),
                'total_vulnerabilities' => count($findings),
                'vulnerabilities' => array_map(fn(Finding $f) => $f->toArray(), $findings)
            ]
        ];

        $jsonOutput = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($jsonOutput !== false) {
            $this->output->writeln($jsonOutput);
        }
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
        if (!is_array($composerJson) || !isset($composerJson['version']) || !is_string($composerJson['version'])) {
            return 'unknown';
        }

        return $composerJson['version'];
    }
}

/**
 * Wrapper class to adapt CustomAudit interface to AbstractAuditService pattern.
 */
class CustomAuditWrapper implements \Dgtlss\Warden\Contracts\AuditService
{
    protected CustomAudit $customAudit;

    /** @var array<int, \Dgtlss\Warden\ValueObjects\Finding> */
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
            $rawFindings = $this->customAudit->getFindings();
            foreach ($rawFindings as $rawFinding) {
                $this->findings[] = \Dgtlss\Warden\ValueObjects\Finding::fromArray(array_merge($rawFinding, [
                    'source' => $this->getName()
                ]));
            }
        }

        return $success;
    }

    /**
     * @return array<int, \Dgtlss\Warden\ValueObjects\Finding>
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    public function shouldRun(): bool
    {
        return $this->customAudit->shouldRun();
    }
}
