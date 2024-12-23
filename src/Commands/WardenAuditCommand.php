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

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit {--silent : Run the audit without sending notifications} {--npm : Run the npm audit}';

    protected $description = 'Performs a composer audit and reports findings via Warden.';

    public function handle()
    {
        $this->info('Running Warden audit...');

        $auditServices = [
            new ComposerAuditService(),
            new EnvAuditService(),
            new StorageAuditService(),
        ];

        if ($this->option('npm')) {
            $auditServices[] = new NpmAuditService();
        }

        $hasFailures = false;
        $allFindings = [];

        foreach ($auditServices as $service) {
            $this->info("Running {$service->getName()} audit...");
            
            if (!$service->run()) {
                $this->error("{$service->getName()} audit failed to run.");
                $hasFailures = true;
                continue;
            }

            $findings = $service->getFindings();
            if (!empty($findings)) {
                $allFindings = array_merge($allFindings, $findings);
            }
        }

        if (!empty($allFindings)) {
            $this->newLine();
            $this->error('Vulnerabilities found.');
            
            foreach ($allFindings as $finding) {
                $this->newLine();
                $this->info('Source: ' . $finding['source']);
                $this->info('Package: ' . $finding['package']);
                $this->info('Title: ' . $finding['title']);
                $this->error('Severity: ' . $finding['severity']);
                if ($finding['cve']) {
                    $this->info('CVE: ' . $finding['cve']);
                    $this->info('Link: https://www.cve.org/CVERecord?id=' . $finding['cve']);
                }
                $finding['affected_versions'] ? $this->info('Affected Versions: ' . $finding['affected_versions']) : null;
            }

            if (!$this->option('silent')) {
                $this->sendNotifications($allFindings);
                $this->newLine();
                $this->info('Notifications sent.');
            }

            return 1;
        }

        $this->info('No vulnerabilities found.');
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
            $this->sendEmailReport($report, $emailRecipients);
        }
    }

    protected function sendEmailReport(array $report, $emailRecipients)
    {
        Mail::send('warden::mail.report', ['report' => $report], function ($message) use ($emailRecipients, $report) {
            $message->to($emailRecipients)
                    ->subject('Warden Audit Report');
        });
    }
}