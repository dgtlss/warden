<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Http;

class PagerDutyChannel implements NotificationChannel
{
    protected ?string $integrationKey;
    protected ?string $apiUrl = 'https://events.pagerduty.com/v2/enqueue';

    public function __construct()
    {
        $integrationKey = config('warden.notifications.pagerduty.integration_key');
        $this->integrationKey = is_string($integrationKey) && $integrationKey !== '' ? $integrationKey : null;
    }

    /**
     * @param array<int, Finding> $findings
     */
    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        // Only send to PagerDuty if there are critical or high severity findings
        $criticalFindings = $this->filterBySeverity($findings, ['critical', 'high']);

        if (empty($criticalFindings)) {
            return;
        }

        $event = $this->buildEvent($criticalFindings);

        if ($this->apiUrl === null || $this->integrationKey === null) {
            return;
        }

        Http::post($this->apiUrl, $event);
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        // Abandoned packages are typically not critical enough for PagerDuty
        // This method exists to satisfy the interface but does not trigger alerts
        return;
    }

    public function isConfigured(): bool
    {
        return $this->integrationKey !== null;
    }

    public function getName(): string
    {
        return 'pagerduty';
    }

    /**
     * Build PagerDuty event payload.
     *
     * @param array<int, Finding> $findings
     * @return array<string, mixed>
     */
    protected function buildEvent(array $findings): array
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';

        $severityCounts = $this->countBySeverity($findings);
        $criticalCount = $severityCounts['critical'];
        $highCount = $severityCounts['high'];

        $severity = $criticalCount > 0 ? 'critical' : 'error';

        $summary = sprintf(
            '[%s] Warden Security Audit: %d critical, %d high severity vulnerabilities',
            $appName,
            $criticalCount,
            $highCount
        );

        $details = [
            'total_findings' => count($findings),
            'critical_findings' => $criticalCount,
            'high_findings' => $highCount,
            'medium_findings' => $severityCounts['medium'],
            'low_findings' => $severityCounts['low'],
            'findings' => array_map(fn(Finding $f) => [
                'package' => $f->package,
                'title' => $f->title,
                'severity' => $f->severity->value,
                'cve' => $f->cve,
            ], array_slice($findings, 0, 20)),
        ];

        return [
            'routing_key' => $this->integrationKey,
            'event_action' => 'trigger',
            'dedup_key' => 'warden-security-audit-' . md5($appName . date('Y-m-d-H')),
            'payload' => [
                'summary' => $summary,
                'severity' => $severity,
                'source' => $appName,
                'component' => 'Warden Security Audit',
                'group' => 'security',
                'class' => 'vulnerability scan',
                'custom_details' => $details,
            ],
            'links' => [],
            'images' => [],
        ];
    }

    /**
     * Filter findings by severity levels.
     *
     * @param array<int, Finding> $findings
     * @param array<int, string> $severities
     * @return array<int, Finding>
     */
    protected function filterBySeverity(array $findings, array $severities): array
    {
        return array_filter($findings, function (Finding $finding) use ($severities) {
            return in_array(strtolower($finding->severity->value), $severities, true);
        });
    }

    /**
     * Count findings by severity.
     *
     * @param array<int, Finding> $findings
     * @return array<string, int>
     */
    protected function countBySeverity(array $findings): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
        ];

        foreach ($findings as $finding) {
            $severity = strtolower($finding->severity->value);

            if ($severity === 'moderate') {
                $severity = 'medium';
            }

            if (isset($counts[$severity])) {
                $counts[$severity]++;
            }
        }

        return $counts;
    }
}
