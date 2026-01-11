<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
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
     * @param array<int, array<string, mixed>> $findings
     */
    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $findings = $this->normalizeItems($findings);
        $recipients = $this->parseRecipients((string) $this->recipients);
        $emailData = $this->prepareEmailData($findings);

        Mail::send('warden::mail.enhanced-report', $emailData, function (Message $message) use ($recipients, $findings): void {
            $message->to($recipients)
                    ->subject($this->generateSubject($findings))
                    ->from($this->fromAddress, $this->fromName);
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

        $abandonedPackages = $this->normalizeItems($abandonedPackages);
        $recipients = $this->parseRecipients((string) $this->recipients);
        $emailData = $this->prepareAbandonedPackagesData($abandonedPackages);

        Mail::send('warden::mail.abandoned-packages', $emailData, function (Message $message) use ($recipients, $abandonedPackages): void {
            $message->to($recipients)
                    ->subject($this->generateAbandonedPackagesSubject($abandonedPackages))
                    ->from($this->fromAddress, $this->fromName);
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
     * @return array<string>
     */
    protected function parseRecipients(string $recipients): array
    {
        return array_map('trim', explode(',', $recipients));
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     * @return array<string, mixed>
     */
    protected function prepareEmailData(array $findings): array
    {
        $appName = config('warden.app_name', 'Application');
        $severityCounts = $this->getSeverityCounts($findings);
        $findingsBySource = $this->groupFindingsBySource($findings);

        return [
            'appName' => $appName,
            'scanDate' => Carbon::now(),
            'totalFindings' => count($findings),
            'severityCounts' => $severityCounts,
            'findingsBySource' => $findingsBySource,
            'findings' => $findings,
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
        $appName = config('warden.app_name', 'Application');

        return [
            'appName' => $appName,
            'scanDate' => Carbon::now(),
            'totalPackages' => count($abandonedPackages),
            'abandonedPackages' => $abandonedPackages,
            'packagesWithReplacements' => array_filter($abandonedPackages, fn($pkg) => !empty($pkg['replacement'])),
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $findings
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
            if (!is_array($finding)) {
                continue;
            }

            $severity = $finding['severity'] ?? 'low';
            if (isset($counts[$severity])) {
                $counts[$severity]++;
            }
        }

        return $counts;
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     * @return array<string, array<int, array<string, mixed>>>
     */
    protected function groupFindingsBySource(array $findings): array
    {
        $grouped = [];

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $source = $finding['source'] ?? 'unknown';
            if (!isset($grouped[$source])) {
                $grouped[$source] = [];
            }

            $grouped[$source][] = $finding;
        }

        return $grouped;
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     */
    protected function getHighestSeverity(array $findings): string
    {
        $severityLevels = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $highest = 'low';
        $highestLevel = 1;

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $severity = $finding['severity'] ?? 'low';
            $level = $severityLevels[$severity] ?? 1;

            if ($level > $highestLevel) {
                $highest = $severity;
                $highestLevel = $level;
            }
        }

        return $highest;
    }

    /**
     * @param array<int, array<string, mixed>> $findings
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
            return sprintf('⚠️ %s critical/high severity vulnerabilities require immediate attention.', $criticalAndHigh);
        }

        if ($severityCounts['medium'] > 0) {
            return sprintf('⚠️ %s medium severity vulnerabilities should be reviewed.', $severityCounts['medium']);
        }

        return $severityCounts['low'] . ' low severity vulnerabilities detected.';
    }

    protected function generateSubject(array $findings): string
    {
        $appName = config('warden.app_name', 'Application');
        $count = count($findings);
        $highestSeverity = $this->getHighestSeverity($findings);

        if ($count === 0) {
            return sprintf('✅ [%s] Warden Security Audit: No Issues Found', $appName);
        }

        $emoji = match($highestSeverity) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium' => '🟡',
            'low' => '🟢',
            default => '⚪'
        };

        return sprintf('%s [%s] Warden Security Alert: %d ', $emoji, $appName, $count) . 
               ($count === 1 ? 'vulnerability' : 'vulnerabilities') . 
               sprintf(' found (%s severity)', $highestSeverity);
    }

    protected function generateAbandonedPackagesSubject(array $abandonedPackages): string
    {
        $appName = (string) config('warden.app_name', 'Application');
        $count = count($abandonedPackages);
        return sprintf('⚠️ [%s] Warden Alert: %d abandoned ', $appName, $count) . 
               ($count === 1 ? 'package' : 'packages') . ' detected';
    }

    /**
     * @param array<int, array<string, mixed>> $items
     * @return array<int, array<string, mixed>>
     */
    private function normalizeItems(array $items): array
    {
        $normalized = [];

        foreach ($items as $item) {
            if (is_array($item)) {
                /** @var array<string, mixed> $item */
                $normalized[] = $item;
            }
        }

        return $normalized;
    }
}
