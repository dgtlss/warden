<?php

namespace Dgtlss\Warden\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Symfony\Component\Process\Process;
use Illuminate\Mail\Mailer;
use Illuminate\Mail\MailManager;

class WardenAuditCommand extends Command
{
    protected $signature = 'warden:audit {--silent : Run the audit without sending notifications}';

    protected $description = 'Performs a composer audit and reports findings via Warden.';

    public function handle()
    {
        $this->info('Running composer audit...');

        $process = new Process(['composer', 'audit', '--format=json']);
        $process->run();

        if (!$process->isSuccessful()) {
            $this->error('Composer audit failed to run.');
            return 2; // Non-zero exit code indicates failure
        }

        $output = $process->getOutput();
        $data = json_decode($output, true);

        if (isset($data['advisories']) && !empty($data['advisories'])) {
            $this->error('Vulnerabilities found.');
            $report = $this->prepareReport($data['advisories']);

            // Check if the --silent option is not set before sending notifications
            if (!$this->option('silent')) {
                $this->sendNotifications($report);
            }

            return 1; // Non-zero exit code to fail the CI/CD pipeline
        } else {
            $this->info('No vulnerabilities found.');
            return 0; // Zero exit code indicates success
            }
    }


    protected function prepareReport(array $advisories)
    {
        $report = "Composer Audit Report\n\n";
        foreach ($advisories as $package => $issues) {
            $report .= "Package: $package\n";
            foreach ($issues as $issue) {
                $report .= "- Title: {$issue['title']}\n";
                $report .= "  CVE: {$issue['cve']}\n";
                $report .= "  Link: {$issue['link']}\n";
                $report .= "  Affected Versions: {$issue['affected_versions']}\n\n";
            }
        }
        return $report;
    }

    protected function sendNotifications($report)
    {
        $webhookUrl = config('warden.webhook_url');
        $emailRecipients = config('warden.email_recipients');

        if ($webhookUrl) {
            Http::post($webhookUrl, ['text' => $report]);
        }

        if ($emailRecipients) {
            $mailer = $this->createCustomMailer();

            $mailer->raw($report, function ($message) use ($emailRecipients) {
                $message->to(explode(',', $emailRecipients))
                        ->subject('Composer Audit Report');
            });
        }
    }

    protected function createCustomMailer()
    {
        $config = [
            'transport' => config('warden.mail.transport', 'smtp'),
            'host' => config('warden.mail.host'),
            'port' => config('warden.mail.port'),
            'encryption' => config('warden.mail.encryption'),
            'username' => config('warden.mail.username'),
            'password' => config('warden.mail.password'),
            'timeout' => null,
            'auth_mode' => null,
        ];

        $fromAddress = config('warden.mail.from_address');
        $fromName = config('warden.mail.from_name');

        $mailManager = app(MailManager::class);

        // Create a custom transport
        $transport = $mailManager->createTransport($config);

        // Create a custom mailer instance
        $mailer = new Mailer(
            $mailManager->getViewFactory(),
            $mailManager->getSwiftMailer($transport),
            app('events')
        );

        // Set the from address
        $mailer->alwaysFrom($fromAddress, $fromName);

        return $mailer;
    }
}
