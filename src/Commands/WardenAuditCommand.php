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
use function Laravel\Prompts\clear;

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit {--silent : Run the audit without sending notifications} {--npm : Run the npm audit}';

    protected $description = 'Performs a composer audit and reports findings via Warden.';

    public function handle()
    {
        clear();

        $composerJson = json_decode(file_get_contents(__DIR__ . '/../../composer.json'), true);
        $this->info('Warden Audit Version ' . $composerJson['version']);

        $auditServices = [
            new ComposerAuditService(),
            new EnvAuditService(),
            new StorageAuditService(),
            new DebugModeAuditService(),
        ];

        if ($this->option('npm')) {
            $auditServices[] = new NpmAuditService();
        }

        $hasFailures = false;
        $allFindings = [];
        $abandonedPackages = [];

        foreach ($auditServices as $service) {
            $this->info("Running {$service->getName()} audit...");
            
            if (!$service->run()) {
                $this->error("{$service->getName()} audit failed to run.");
                if ($service instanceof ComposerAuditService) {
                    $this->error("Error: " . collect($service->getFindings())->last()['error'] ?? 'Unknown error');
                }
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

        // Handle abandoned packages separately
        if (!empty($abandonedPackages)) {
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

        if (!empty($allFindings)) {
            $this->error(count($allFindings) . ' vulnerabilities found.');
            
            $headers = ['Source', 'Package ', 'Title', 'Severity', 'CVE', 'Link', 'Affected Versions'];
            $rows = [];

            foreach ($allFindings as $finding) {
                $row = [
                    $finding['source'],
                    $finding['package'],
                    $finding['title'],
                    $finding['severity'],
                    $finding['cve'] ?? '-',
                    $finding['cve'] ? 'https://www.cve.org/CVERecord?id=' . $finding['cve'] : '-',
                    $finding['affected_versions'] ?? '-'
                ];
                $rows[] = $row;
            }

            table(
                headers: $headers,
                rows: $rows
            );

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


    protected function prepareReport(array $advisories)
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

    protected function sendNotifications(array $report)
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        if ($webhookUrl) {
            Http::post($webhookUrl, ['text' => $report]);
        }

        if ($emailRecipients) {
            // Convert comma-separated string to array if needed
            $recipients = is_string($emailRecipients) ? explode(',', $emailRecipients) : $emailRecipients;
            $this->sendEmailReport($report, $recipients);
        }
    }

    protected function sendEmailReport(array $report, $emailRecipients)
    {
        Mail::send('warden::mail.report', ['report' => $report], function ($message) use ($emailRecipients, $report) {
            $message->to($emailRecipients)
                    ->subject('Warden Audit Report');
        });
    }

    protected function sendAbandonedPackagesNotification(array $abandonedPackages)
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
