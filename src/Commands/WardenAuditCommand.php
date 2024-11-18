<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Symfony\Component\Process\Process;

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit {--silent : Run the audit without sending notifications}';

    protected $description = 'Performs a composer audit and reports findings via Warden.';

    public function handle()
    {
        $this->info('Running Warden audit...');

        $process = new Process(['composer', 'audit', '--format=json']);
        $process->run();

        if (!$process->isSuccessful()) {
            $this->error('Warden audit failed to run.');
            return 2; // Non-zero exit code indicates failure
        }

        $output = $process->getOutput();
        $data = json_decode($output, true);

        if (isset($data['advisories']) && !empty($data['advisories'])) {
            $this->newLine();
            $this->error('Vulnerabilities found.');
            $report = $this->prepareReport($data['advisories']);

            $this->newLine();
            foreach($report as $package => $issues) {
                $this->info('Package: '.$package);
                foreach($issues as $issue) {
                    $this->info('Title: '.$issue['title']);
                    $this->info('CVE: '.$issue['cve']);
                    $this->info('Link: https://www.cve.org/CVERecord?id='.$issue['cve']);
                    $this->info('Affected Versions: '.$issue['affected_versions']);
                }
            }

            $this->newLine();
            $this->info('Warden audit completed.');

            // Check if the --silent option is not set before sending notifications
            if (!$this->option('silent')) {
                $this->sendNotifications($report);
                $this->newLine();
                $this->info('Notifications sent.');
            }

            $this->newLine();
            $this->info('⭐️ If you found this useful, please consider starring the project on GitHub: https://github.com/dgtlss/warden');

            return 1; // Non-zero exit code to fail the CI/CD pipeline
        } else {
            $this->info('No vulnerabilities found.');
            return 0; // Zero exit code indicates success
            }
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
