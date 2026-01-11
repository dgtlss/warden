<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Mail;
use Illuminate\Mail\Message;
use Carbon\Carbon;

class EmailChannel implements NotificationChannel
{
    protected ?string $recipients;

    protected ?string $fromAddress;

    protected ?string $fromName;

    public function __construct()
    {
        $recipients = config('warden.notifications.email.recipients');
        $fromAddress = config('warden.notifications.email.from_address');
        $fromName = config('warden.notifications.email.from_name', 'Warden Security');

        $this->recipients = is_string($recipients) ? $recipients : null;
        $this->fromAddress = is_string($fromAddress) ? $fromAddress : null;
        $this->fromName = is_string($fromName) ? $fromName : 'Warden Security';
    }

    /**
     * @param array<int, Finding> $findings
     */
    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $recipients = $this->parseRecipients((string) $this->recipients);
        $emailData = $this->prepareEmailData($findings);

        Mail::send('warden::mail.enhanced-report', $emailData, function (Message $message) use ($recipients, $findings): void {
            $message->to($recipients)
                    ->subject($this->generateSubject($findings))
                    ->from((string) $this->fromAddress, $this->fromName);
        });
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $recipients = $this->parseRecipients((string) $this->recipients);
        $emailData = $this->prepareAbandonedPackagesData($abandonedPackages);

        Mail::send('warden::mail.abandoned-packages', $emailData, function (Message $message) use ($recipients, $abandonedPackages): void {
            $message->to($recipients)
                    ->subject($this->generateAbandonedPackagesSubject($abandonedPackages))
                    ->from((string) $this->fromAddress, $this->fromName);
        });
    }

    public function isConfigured(): bool
    {
        return !in_array($this->recipients, [null, '', '0'], true) && !in_array($this->fromAddress, [null, '', '0'], true);
    }

    public function getName(): string
    {
        return 'Email';
    }

    /**
     * @return array<int, string>
     */
    protected function parseRecipients(string $recipients): array
    {
        return array_map('trim', explode(',', $recipients));
    }

    /**
     * @param array<int, Finding> $findings
     * @return array<string, mixed>
     */
    protected function prepareEmailData(array $findings): array
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        $severityCounts = $this->getSeverityCounts($findings);
        $findingsBySource = $this->groupFindingsBySource($findings);

        return [
            'appName' => $appName,
            'scanDate' => Carbon::now(),
            'totalFindings' => count($findings),
            'severityCounts' => $severityCounts,
            'findingsBySource' => $findingsBySource,
            'findings' => array_map(fn(Finding $f) => $f->toArray(), $findings),
            'highestSeverity' => $this->getHighestSeverity($findings),
            'summary' => $this->generateSummary($findings, $severityCounts),
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     * @return array<string, mixed>
     */
    protected function prepareAbandonedPackagesData(array $abandonedPackages): array
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';

        return [
            'appName' => $appName,
            'scanDate' => Carbon::now(),
            'totalPackages' => count($abandonedPackages),
            'abandonedPackages' => $abandonedPackages,
            'packagesWithReplacements' => array_filter($abandonedPackages, fn(array $pkg) => !empty($pkg['replacement'])),
        ];
    }

    /**
     * @param array<int, Finding> $findings
     * @return array{critical:int,high:int,medium:int,low:int}
     */
    protected function getSeverityCounts(array $findings): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0
        ];

        foreach ($findings as $finding) {
            $severity = $finding->severity->value;
            if ($severity === 'moderate') {
                $severity = 'medium';
            }
            if (isset($counts[$severity])) {
                $counts[$severity]++;
            }
        }

        return $counts;
    }

    /**
     * @param array<int, Finding> $findings
     * @return array<string, array<int, array<string, mixed>>>
     */
    protected function groupFindingsBySource(array $findings): array
    {
        $grouped = [];

        foreach ($findings as $finding) {
            $source = $finding->source;
            if (!isset($grouped[$source])) {
                $grouped[$source] = [];
            }

            $grouped[$source][] = $finding->toArray();
        }

        return $grouped;
    }

    /**
     * @param array<int, Finding> $findings
     */
    protected function getHighestSeverity(array $findings): string
    {
        $severityLevels = ['critical' => 4, 'high' => 3, 'medium' => 2, 'moderate' => 2, 'low' => 1];
        $highest = 'low';
        $highestLevel = 1;

        foreach ($findings as $finding) {
            $severity = $finding->severity->value;
            $level = $severityLevels[$severity] ?? 1;

            if ($level > $highestLevel) {
                $highest = $severity;
                $highestLevel = $level;
            }
        }

        return $highest;
    }

    /**
     * @param array<int, Finding> $findings
     * @param array{critical:int,high:int,medium:int,low:int} $severityCounts
     */
    protected function generateSummary(array $findings, array $severityCounts): string
    {
        $totalFindings = count($findings);

        if ($totalFindings === 0) {
            return 'No security vulnerabilities detected.';
        }

        $criticalAndHigh = $severityCounts['critical'] + $severityCounts['high'];

        if ($criticalAndHigh > 0) {
            return sprintf('⚠️ %s critical/high severity vulnerabilities require immediate attention.', (string) $criticalAndHigh);
        }

        if ($severityCounts['medium'] > 0) {
            return sprintf('⚠️ %s medium severity vulnerabilities should be reviewed.', (string) $severityCounts['medium']);
        }

        return $severityCounts['low'] . ' low severity vulnerabilities detected.';
    }

    /**
     * @param array<int, Finding> $findings
     */
    protected function generateSubject(array $findings): string
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        $count = count($findings);
        $highestSeverity = $this->getHighestSeverity($findings);

        if ($count === 0) {
            return sprintf('✅ [%s] Warden Security Audit: No Issues Found', $appName);
        }

        $emoji = match($highestSeverity) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium', 'moderate' => '🟡',
            'low' => '🟢',
            default => '⚪'
        };

        return sprintf('%s [%s] Warden Security Alert: %d ', $emoji, $appName, $count) . 
               ($count === 1 ? 'vulnerability' : 'vulnerabilities') . 
               sprintf(' found (%s severity)', $highestSeverity);
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    protected function generateAbandonedPackagesSubject(array $abandonedPackages): string
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        $count = count($abandonedPackages);
        return sprintf('⚠️ [%s] Warden Alert: %d abandoned ', $appName, $count) . 
               ($count === 1 ? 'package' : 'packages') . ' detected';
    }
}