<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Symfony\Component\Process\Process;
use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Services\Audits\EnvAuditService;
use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use function Laravel\Prompts\info;
use function Laravel\Prompts\table;

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit 
    {--silent : Run the audit without sending notifications} 
    {--npm : Run the npm audit}
    {--ignore-abandoned : Ignore abandoned packages, without throwing an error}';

    protected $description = 'Performs a composer audit and reports findings via Warden.';

    /**
     * Execute the console command.
     *
     * @return int Exit code: 0 for success, 1 for vulnerabilities found, 2 for audit failures
     */
    public function handle(): int
    {
        // Extract version display to a separate method
        $this->displayVersion();
        
        // Initialize audit services
        $auditServices = $this->initializeAuditServices();

        $hasFailures = false;
        $allFindings = [];
        $abandonedPackages = [];

        // Run all audit services and collect results
        foreach ($auditServices as $service) {
            $this->info("Running {$service->getName()} audit...");
            
            if (!$service->run()) {
                $this->handleAuditFailure($service);
                $hasFailures = true;
                continue;
            }

            $findings = $service->getFindings();
            if (!empty($findings)) {
                $allFindings = array_merge($allFindings, $findings);
            }

            // Collect abandoned packages
            if ($service instanceof ComposerAuditService) {
                $abandonedPackages = $service->getAbandonedPackages();
            }
        }

        // Handle abandoned packages
        $this->handleAbandonedPackages($abandonedPackages);

        // Display and handle findings
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
            $this->error("Error: " . collect($service->getFindings())->last()['error'] ?? 'Unknown error');
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
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        if ($webhookUrl) {
            $this->sendWebhookNotification($webhookUrl, $findings);
        }

        if ($emailRecipients) {
            // Convert comma-separated string to array if needed
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
}
