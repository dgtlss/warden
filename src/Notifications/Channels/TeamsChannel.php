<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Http;

class TeamsChannel implements NotificationChannel
{
    protected ?string $webhookUrl;

    public function __construct()
    {
        $webhookUrl = config('warden.notifications.teams.webhook_url');
        $this->webhookUrl = is_string($webhookUrl) && $webhookUrl !== '' ? $webhookUrl : null;
    }

    /**
     * @param array<int, Finding> $findings
     */
    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $card = $this->buildFindingsCard($findings);
        
        if ($this->webhookUrl === null) {
            return;
        }
        
        Http::post($this->webhookUrl, $card);
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $card = $this->buildAbandonedPackagesCard($abandonedPackages);
        
        if ($this->webhookUrl === null) {
            return;
        }
        
        Http::post($this->webhookUrl, $card);
    }

    public function isConfigured(): bool
    {
        return !in_array($this->webhookUrl, [null, '', '0'], true);
    }

    public function getName(): string
    {
        return 'Microsoft Teams';
    }

    /**
     * @param array<int, Finding> $findings
     * @return array<string, mixed>
     */
    protected function buildFindingsCard(array $findings): array
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        $totalFindings = count($findings);
        $severityCounts = $this->getSeverityCounts($findings);
        $highestSeverity = $this->getHighestSeverity($findings);
        
        if ($totalFindings === 0) {
            return $this->buildSuccessCard();
        }

        $themeColor = $this->getSeverityColor($highestSeverity);
        $summary = $this->generateSummary($findings, $severityCounts);

        return [
            '@type' => 'MessageCard',
            '@context' => 'http://schema.org/extensions',
            'themeColor' => $themeColor,
            'summary' => sprintf('[%s] Warden Security Alert: %d vulnerabilities found', $appName, $totalFindings),
            'sections' => [
                [
                    'activityTitle' => sprintf('🛡️ **[%s] Warden Security Audit Report**', $appName),
                    'activitySubtitle' => date('F j, Y \a\t g:i A'),
                    'activityImage' => 'https://raw.githubusercontent.com/dgtlss/warden/refs/heads/main/public/warden-logo.png',
                    'facts' => [
                        [
                            'name' => 'Total Vulnerabilities',
                            'value' => (string)$totalFindings
                        ],
                        [
                            'name' => 'Highest Severity',
                            'value' => ucfirst($highestSeverity)
                        ],
                        [
                            'name' => 'Critical',
                            'value' => (string)$severityCounts['critical']
                        ],
                        [
                            'name' => 'High',
                            'value' => (string)$severityCounts['high']
                        ],
                        [
                            'name' => 'Medium',
                            'value' => (string)$severityCounts['medium']
                        ],
                        [
                            'name' => 'Low',
                            'value' => (string)$severityCounts['low']
                        ]
                    ],
                    'markdown' => true
                ],
                [
                    'text' => sprintf('**%s**', $summary),
                    'markdown' => true
                ]
            ]
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     * @return array<string, mixed>
     */
    protected function buildAbandonedPackagesCard(array $abandonedPackages): array
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        $totalPackages = count($abandonedPackages);
        $packagesWithReplacements = array_filter($abandonedPackages, fn(array $pkg) => !empty($pkg['replacement']));

        $packagesText = '';
        foreach (array_slice($abandonedPackages, 0, 10) as $package) { // Limit to prevent size issues
            $packageName = is_string($package['package'] ?? null) ? $package['package'] : 'unknown';
            /** @var string|null $replacement */
            $replacement = isset($package['replacement']) && is_string($package['replacement']) ? $package['replacement'] : null;

            $packagesText .= sprintf('**%s**  %s', $packageName, PHP_EOL);
            if ($replacement !== null) {
                $packagesText .= sprintf('→ Recommended: %s  %s', $replacement, PHP_EOL);
            } else {
                $packagesText .= "→ No replacement suggested  \n";
            }

            $packagesText .= "  \n";
        }

        if (count($abandonedPackages) > 10) {
            $remaining = count($abandonedPackages) - 10;
            $packagesText .= sprintf('*...and %d more packages*', $remaining);
        }

        return [
            '@type' => 'MessageCard',
            '@context' => 'http://schema.org/extensions',
            'themeColor' => 'FF8C00', // Orange for warnings
            'summary' => sprintf('[%s] Warden Alert: %d abandoned packages detected', $appName, $totalPackages),
            'sections' => [
                [
                    'activityTitle' => sprintf('⚠️ **[%s] Abandoned Packages Detected**', $appName),
                    'activitySubtitle' => date('F j, Y \a\t g:i A'),
                    'activityImage' => 'https://raw.githubusercontent.com/dgtlss/warden/refs/heads/main/public/warden-logo.png',
                    'facts' => [
                        [
                            'name' => 'Total Abandoned',
                            'value' => (string)$totalPackages
                        ],
                        [
                            'name' => 'With Replacements',
                            'value' => (string)count($packagesWithReplacements)
                        ]
                    ],
                    'markdown' => true
                ],
                [
                    'activityTitle' => '📦 Package Details',
                    'text' => $packagesText,
                    'markdown' => true
                ]
            ],
            'potentialAction' => [
                [
                    '@type' => 'OpenUri',
                    'name' => 'View Documentation',
                    'targets' => [
                        [
                            'os' => 'default',
                            'uri' => 'https://github.com/dgtlss/warden'
                        ]
                    ]
                ]
            ]
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function buildSuccessCard(): array
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        
        return [
            '@type' => 'MessageCard',
            '@context' => 'http://schema.org/extensions',
            'themeColor' => '00FF00', // Green for success
            'summary' => sprintf('[%s] Warden Security Audit: All Clear', $appName),
            'sections' => [
                [
                    'activityTitle' => sprintf('✅ **[%s] Security Audit Complete**', $appName),
                    'activitySubtitle' => date('F j, Y \a\t g:i A'),
                    'activityImage' => 'https://raw.githubusercontent.com/dgtlss/warden/refs/heads/main/public/warden-logo.png',
                    'text' => '**No security vulnerabilities detected!**  \nYour application dependencies are secure.',
                    'markdown' => true
                ]
            ]
        ];
    }

    /**
     * @param array<int, Finding> $findings
     * @return array{critical:int,high:int,medium:int,low:int}
     */
    protected function getSeverityCounts(array $findings): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        
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

    protected function getSeverityColor(string $severity): string
    {
        return match($severity) {
            'critical' => 'FF0000', // Red
            'high' => 'FF8C00',     // Orange
            'medium', 'moderate' => 'FFD700',   // Gold
            'low' => '32CD32',      // Green
            default => '808080'     // Gray
        };
    }

    protected function getSeverityIcon(string $severity): string
    {
        return match($severity) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium', 'moderate' => '🟡',
            'low' => '🟢',
            default => '⚪'
        };
    }

    /**
     * @param array<int, Finding> $findings
     * @return array<string, array<int, Finding>>
     */
    protected function groupFindingsBySource(array $findings): array
    {
        $grouped = [];
        
        foreach ($findings as $finding) {
            $source = $finding->source;
            if (!isset($grouped[$source])) {
                $grouped[$source] = [];
            }

            $grouped[$source][] = $finding;
        }

        return $grouped;
    }

    /**
     * @param array<int, Finding> $findings
     * @param array{critical:int,high:int,medium:int,low:int} $severityCounts
     */
    protected function generateSummary(array $findings, array $severityCounts): string
    {
        $criticalAndHigh = $severityCounts['critical'] + $severityCounts['high'];
        
        if ($criticalAndHigh > 0) {
            return $criticalAndHigh . ' critical/high severity vulnerabilities require immediate attention';
        }

        if ($severityCounts['medium'] > 0) {
            return $severityCounts['medium'] . ' medium severity vulnerabilities should be reviewed';
        }

        return $severityCounts['low'] . ' low severity vulnerabilities detected';
    }

}
