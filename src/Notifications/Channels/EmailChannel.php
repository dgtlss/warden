<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Illuminate\Support\Facades\Mail;
use Carbon\Carbon;

class EmailChannel implements NotificationChannel
{
    protected ?string $recipients;
    protected ?string $fromAddress;
    protected ?string $fromName;

    public function __construct()
    {
        $this->recipients = config('warden.notifications.email.recipients');
        $this->fromAddress = config('warden.notifications.email.from_address');
        $this->fromName = config('warden.notifications.email.from_name', 'Warden Security');
    }

    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $recipients = $this->parseRecipients($this->recipients);
        $emailData = $this->prepareEmailData($findings);

        Mail::send('warden::mail.enhanced-report', $emailData, function ($message) use ($recipients, $findings) {
            $message->to($recipients)
                    ->subject($this->generateSubject($findings))
                    ->from($this->fromAddress, $this->fromName);
        });
    }

    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $recipients = $this->parseRecipients($this->recipients);
        $emailData = $this->prepareAbandonedPackagesData($abandonedPackages);

        Mail::send('warden::mail.abandoned-packages', $emailData, function ($message) use ($recipients, $abandonedPackages) {
            $message->to($recipients)
                    ->subject($this->generateAbandonedPackagesSubject($abandonedPackages))
                    ->from($this->fromAddress, $this->fromName);
        });
    }

    public function isConfigured(): bool
    {
        return !empty($this->recipients) && !empty($this->fromAddress);
    }

    public function getName(): string
    {
        return 'Email';
    }

    protected function parseRecipients(string $recipients): array
    {
        return array_map('trim', explode(',', $recipients));
    }

    protected function prepareEmailData(array $findings): array
    {
        $severityCounts = $this->getSeverityCounts($findings);
        $findingsBySource = $this->groupFindingsBySource($findings);
        
        return [
            'scanDate' => Carbon::now(),
            'totalFindings' => count($findings),
            'severityCounts' => $severityCounts,
            'findingsBySource' => $findingsBySource,
            'findings' => $findings,
            'highestSeverity' => $this->getHighestSeverity($findings),
            'summary' => $this->generateSummary($findings, $severityCounts),
        ];
    }

    protected function prepareAbandonedPackagesData(array $abandonedPackages): array
    {
        return [
            'scanDate' => Carbon::now(),
            'totalPackages' => count($abandonedPackages),
            'abandonedPackages' => $abandonedPackages,
            'packagesWithReplacements' => array_filter($abandonedPackages, fn($pkg) => !empty($pkg['replacement'])),
        ];
    }

    protected function getSeverityCounts(array $findings): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0
        ];

        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            if (isset($counts[$severity])) {
                $counts[$severity]++;
            }
        }

        return $counts;
    }

    protected function groupFindingsBySource(array $findings): array
    {
        $grouped = [];
        
        foreach ($findings as $finding) {
            $source = $finding['source'] ?? 'unknown';
            if (!isset($grouped[$source])) {
                $grouped[$source] = [];
            }
            $grouped[$source][] = $finding;
        }

        return $grouped;
    }

    protected function getHighestSeverity(array $findings): string
    {
        $severityLevels = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $highest = 'low';
        $highestLevel = 1;

        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            $level = $severityLevels[$severity] ?? 1;
            
            if ($level > $highestLevel) {
                $highest = $severity;
                $highestLevel = $level;
            }
        }

        return $highest;
    }

    protected function generateSummary(array $findings, array $severityCounts): string
    {
        $totalFindings = count($findings);
        
        if ($totalFindings === 0) {
            return 'No security vulnerabilities detected.';
        }

        $criticalAndHigh = $severityCounts['critical'] + $severityCounts['high'];
        
        if ($criticalAndHigh > 0) {
            return "⚠️ {$criticalAndHigh} critical/high severity vulnerabilities require immediate attention.";
        }

        if ($severityCounts['medium'] > 0) {
            return "⚠️ {$severityCounts['medium']} medium severity vulnerabilities should be reviewed.";
        }

        return "{$severityCounts['low']} low severity vulnerabilities detected.";
    }

    protected function generateSubject(array $findings): string
    {
        $count = count($findings);
        $highestSeverity = $this->getHighestSeverity($findings);
        
        if ($count === 0) {
            return '✅ Warden Security Audit: No Issues Found';
        }

        $emoji = match($highestSeverity) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium' => '🟡',
            'low' => '🟢',
            default => '⚪'
        };

        return "{$emoji} Warden Security Alert: {$count} " . 
               ($count === 1 ? 'vulnerability' : 'vulnerabilities') . 
               " found ({$highestSeverity} severity)";
    }

    protected function generateAbandonedPackagesSubject(array $abandonedPackages): string
    {
        $count = count($abandonedPackages);
        return "⚠️ Warden Alert: {$count} abandoned " . 
               ($count === 1 ? 'package' : 'packages') . " detected";
    }
}