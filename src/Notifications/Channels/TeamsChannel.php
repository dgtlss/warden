<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Illuminate\Support\Facades\Http;

class TeamsChannel implements NotificationChannel
{
    use \Dgtlss\Warden\Notifications\Concerns\HasSeverityHelpers;
    protected ?string $webhookUrl;

    public function __construct()
    {
        $this->webhookUrl = config('warden.notifications.teams.webhook_url');
    }

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
     * @param array<array<string, mixed>> $findings
     * @return array<string, mixed>
     */
    protected function buildFindingsCard(array $findings): array
    {
        $appName = config('warden.app_name', 'Application');
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
     * @param array<array<string, mixed>> $abandonedPackages
     * @return array<string, mixed>
     */
    protected function buildAbandonedPackagesCard(array $abandonedPackages): array
    {
        $appName = config('warden.app_name', 'Application');
        $totalPackages = count($abandonedPackages);
        $packagesWithReplacements = array_filter($abandonedPackages, fn($pkg) => !empty($pkg['replacement']));

        $packagesText = '';
        foreach (array_slice($abandonedPackages, 0, 10) as $package) { // Limit to prevent size issues
            $packagesText .= "**{$package['package']}**  \n";
            if (!empty($package['replacement'])) {
                $packagesText .= "→ Recommended: {$package['replacement']}  \n";
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
        $appName = config('warden.app_name', 'Application');
        
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

    protected function getSeverityColor(string $severity): string
    {
        return match($severity) {
            'critical' => 'FF0000', // Red
            'high' => 'FF8C00',     // Orange
            'medium' => 'FFD700',   // Gold
            'low' => '32CD32',      // Green
            default => '808080'     // Gray
        };
    }

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