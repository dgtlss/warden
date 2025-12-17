<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Illuminate\Support\Facades\Http;

class TeamsChannel implements NotificationChannel
{
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
        return !empty($this->webhookUrl);
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
            'summary' => "[{$appName}] Warden Security Alert: {$totalFindings} vulnerabilities found",
            'sections' => [
                [
                    'activityTitle' => "🛡️ **[{$appName}] Warden Security Audit Report**",
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
                    'text' => "**{$summary}**",
                    'markdown' => true
                ]
            ]
        ];

        // Add detailed findings sections (limit to prevent message size issues)
        $sectionsToAdd = [];
        $findingsBySource = $this->groupFindingsBySource($findings);
        $addedFindings = 0;
        $maxFindings = 10; // Teams has message size limits

        foreach ($findingsBySource as $source => $sourceFindings) {
            if ($addedFindings >= $maxFindings) {
                break;
            }

            $findingsText = '';
            $remainingSpace = $maxFindings - $addedFindings;
            $findingsToShow = array_slice($sourceFindings, 0, $remainingSpace);

            foreach ($findingsToShow as $finding) {
                $severity = ucfirst($finding['severity'] ?? 'low');
                $severityIcon = $this->getSeverityIcon($finding['severity'] ?? 'low');
                
                $findingsText .= "**{$severityIcon} {$severity}** - {$finding['package']}  \n";
                $findingsText .= "{$finding['title']}  \n";
                
                if (!empty($finding['cve'])) {
                    $findingsText .= "CVE: [{$finding['cve']}](https://www.cve.org/CVERecord?id={$finding['cve']})  \n";
                }
                
                $findingsText .= "  \n";
                $addedFindings++;
            }

            if (count($sourceFindings) > count($findingsToShow)) {
                $remaining = count($sourceFindings) - count($findingsToShow);
                $findingsText .= "*...and {$remaining} more {$source} issues*  \n";
            }

            $sectionsToAdd[] = [
                'activityTitle' => "📦 " . ucfirst($source) . " Issues",
                'text' => $findingsText,
                'markdown' => true
            ];
        }

        $card['sections'] = array_merge($card['sections'], $sectionsToAdd);

        // Add action buttons
        $card['potentialAction'] = [
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
        ];

        return $card;
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
            $packagesText .= "*...and {$remaining} more packages*";
        }

        return [
            '@type' => 'MessageCard',
            '@context' => 'http://schema.org/extensions',
            'themeColor' => 'FF8C00', // Orange for warnings
            'summary' => "[{$appName}] Warden Alert: {$totalPackages} abandoned packages detected",
            'sections' => [
                [
                    'activityTitle' => "⚠️ **[{$appName}] Abandoned Packages Detected**",
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
            'summary' => "[{$appName}] Warden Security Audit: All Clear",
            'sections' => [
                [
                    'activityTitle' => "✅ **[{$appName}] Security Audit Complete**",
                    'activitySubtitle' => date('F j, Y \a\t g:i A'),
                    'activityImage' => 'https://raw.githubusercontent.com/dgtlss/warden/refs/heads/main/public/warden-logo.png',
                    'text' => '**No security vulnerabilities detected!**  \nYour application dependencies are secure.',
                    'markdown' => true
                ]
            ]
        ];
    }

    protected function getSeverityCounts(array $findings): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        
        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            if (isset($counts[$severity])) {
                $counts[$severity]++;
            }
        }
        
        return $counts;
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

    protected function getSeverityIcon(string $severity): string
    {
        return match($severity) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium' => '🟡',
            'low' => '🟢',
            default => '⚪'
        };
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

    protected function generateSummary(array $findings, array $severityCounts): string
    {
        $criticalAndHigh = $severityCounts['critical'] + $severityCounts['high'];
        
        if ($criticalAndHigh > 0) {
            return "{$criticalAndHigh} critical/high severity vulnerabilities require immediate attention";
        }

        if ($severityCounts['medium'] > 0) {
            return "{$severityCounts['medium']} medium severity vulnerabilities should be reviewed";
        }

        return "{$severityCounts['low']} low severity vulnerabilities detected";
    }
}