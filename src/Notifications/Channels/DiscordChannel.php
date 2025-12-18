<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Illuminate\Support\Facades\Http;

class DiscordChannel implements NotificationChannel
{
    protected ?string $webhookUrl;

    public function __construct()
    {
        $this->webhookUrl = config('warden.notifications.discord.webhook_url');
    }

    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $appName = config('warden.app_name', 'Application');
        $embeds = $this->buildFindingsEmbeds($findings);
        
        if ($this->webhookUrl === null) {
            return;
        }
        
        Http::post($this->webhookUrl, [
            'username' => 'Warden Security',
            'avatar_url' => 'https://raw.githubusercontent.com/dgtlss/warden/main/public/warden-logo.png',
            'content' => sprintf('🚨 **[%s] Security Audit Alert** - %d vulnerabilities found', $appName, count($findings)),
            'embeds' => $embeds
        ]);
    }

    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $appName = config('warden.app_name', 'Application');
        $embed = $this->buildAbandonedPackagesEmbed($abandonedPackages);
        
        if ($this->webhookUrl === null) {
            return;
        }
        
        Http::post($this->webhookUrl, [
            'username' => 'Warden Security',
            'avatar_url' => 'https://raw.githubusercontent.com/dgtlss/warden/main/public/warden-logo.png',
            'content' => sprintf('⚠️ **[%s] Abandoned Packages Alert** - %d packages need attention', $appName, count($abandonedPackages)),
            'embeds' => [$embed]
        ]);
    }

    public function isConfigured(): bool
    {
        return !in_array($this->webhookUrl, [null, '', '0'], true);
    }

    public function getName(): string
    {
        return 'Discord';
    }

    /**
     * @param array<array<string, mixed>> $findings
     * @return array<array<string, mixed>>
     */
    protected function buildFindingsEmbeds(array $findings): array
    {
        $embeds = [];
        $findingsBySource = [];

        // Group findings by source
        foreach ($findings as $finding) {
            $source = $finding['source'] ?? 'Unknown';
            $findingsBySource[$source][] = $finding;
        }

        // Create embeds for each source
        foreach ($findingsBySource as $source => $sourceFindings) {
            $fields = [];

            foreach (array_slice($sourceFindings, 0, 10) as $finding) { // Discord limit: 25 fields per embed
                $severity = ucfirst($finding['severity'] ?? 'low');
                $severityEmoji = match($finding['severity'] ?? 'low') {
                    'critical' => '🔴',
                    'high' => '🟠',
                    'medium' => '🟡',
                    'low' => '🟢',
                    default => '⚪'
                };

                $value = $finding['title'] ?? 'Unknown vulnerability';
                if (!empty($finding['cve'])) {
                    $value .= sprintf("\n[CVE: %s](https://www.cve.org/CVERecord?id=%s)", $finding['cve'], $finding['cve']);
                }

                $fields[] = [
                    'name' => sprintf('%s %s - %s', $severityEmoji, $severity, $finding['package'] ?? 'Unknown'),
                    'value' => $value,
                    'inline' => false
                ];
            }

            if (count($sourceFindings) > 10) {
                $fields[] = [
                    'name' => '➕ More',
                    'value' => sprintf('And %d more vulnerabilities...', count($sourceFindings) - 10),
                    'inline' => false
                ];
            }

            $appName = config('warden.app_name', 'Application');

            $embeds[] = [
                'title' => sprintf('[%s] %s Audit Results', $appName, $source),
                'color' => $this->getSeverityColor($sourceFindings),
                'fields' => $fields,
                'timestamp' => date('c'),
                'footer' => [
                    'text' => 'Warden Security Scanner',
                    'icon_url' => 'https://raw.githubusercontent.com/dgtlss/warden/main/public/warden-logo.png'
                ]
            ];
        }

        return array_slice($embeds, 0, 10); // Discord limit: 10 embeds per message
    }

    /**
     * @param array<array<string, mixed>> $abandonedPackages
     * @return array<string, mixed>
     */
    protected function buildAbandonedPackagesEmbed(array $abandonedPackages): array
    {
        $fields = [];
        
        foreach (array_slice($abandonedPackages, 0, 20) as $package) {
            $value = $package['replacement'] 
                ? sprintf('Recommended: `%s`', $package['replacement'])
                : 'No replacement suggested';
                
            $fields[] = [
                'name' => $package['package'],
                'value' => $value,
                'inline' => true
            ];
        }
        
        if (count($abandonedPackages) > 20) {
            $fields[] = [
                'name' => '➕ More',
                'value' => sprintf('And %d more abandoned packages...', count($abandonedPackages) - 20),
                'inline' => false
            ];
        }
        
        $appName = config('warden.app_name', 'Application');
        
        return [
            'title' => sprintf('⚠️ [%s] Abandoned Packages Found', $appName),
            'description' => 'The following packages are no longer maintained and may contain unpatched vulnerabilities.',
            'color' => 0xFF9800, // Orange
            'fields' => $fields,
            'timestamp' => date('c'),
            'footer' => [
                'text' => 'Warden Security Scanner',
                'icon_url' => 'https://raw.githubusercontent.com/dgtlss/warden/main/public/warden-logo.png'
            ]
        ];
    }

    protected function getSeverityColor(array $findings): int
    {
        $hasCritical = false;
        $hasHigh = false;
        $hasMedium = false;

        foreach ($findings as $finding) {
            switch ($finding['severity'] ?? 'low') {
                case 'critical':
                    $hasCritical = true;
                    break;
                case 'high':
                    $hasHigh = true;
                    break;
                case 'medium':
                    $hasMedium = true;
                    break;
            }
        }

        if ($hasCritical) {
            return 0xFF0000; // Red
        } elseif ($hasHigh) {
            return 0xFF6B00; // Orange
        } elseif ($hasMedium) {
            return 0xFFD700; // Yellow
        }

        return 0x00FF00; // Green
    }
} 