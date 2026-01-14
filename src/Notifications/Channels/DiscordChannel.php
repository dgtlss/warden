<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\Notifications\Channels\Concerns\SignsWebhooks;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Http;

class DiscordChannel implements NotificationChannel
{
    use SignsWebhooks;

    protected ?string $webhookUrl;

    public function __construct()
    {
        $webhookUrl = config('warden.notifications.discord.webhook_url');
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

        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        $embeds = $this->buildFindingsEmbeds($findings);

        if ($this->webhookUrl === null) {
            return;
        }

        $payload = [
            'username' => 'Warden Security',
            'avatar_url' => 'https://raw.githubusercontent.com/dgtlss/warden/main/public/warden-logo.png',
            'content' => sprintf('🚨 **[%s] Security Audit Alert** - %d vulnerabilities found', $appName, count($findings)),
            'embeds' => $embeds,
        ];

        $this->sendSignedPost($this->webhookUrl, $payload);
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        $embed = $this->buildAbandonedPackagesEmbed($abandonedPackages);

        if ($this->webhookUrl === null) {
            return;
        }

        $payload = [
            'username' => 'Warden Security',
            'avatar_url' => 'https://raw.githubusercontent.com/dgtlss/warden/main/public/warden-logo.png',
            'content' => sprintf('⚠️ **[%s] Abandoned Packages Alert** - %d packages need attention', $appName, count($abandonedPackages)),
            'embeds' => [$embed],
        ];

        $this->sendSignedPost($this->webhookUrl, $payload);
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
     * @param array<int, Finding> $findings
     * @return array<int, array<string, mixed>>
     */
    protected function buildFindingsEmbeds(array $findings): array
    {
        $embeds = [];
        /** @var array<string, array<int, Finding>> $findingsBySource */
        $findingsBySource = [];

        // Group findings by source
        foreach ($findings as $finding) {
            $source = $finding->source;
            $findingsBySource[$source][] = $finding;
        }

        foreach ($findingsBySource as $source => $sourceFindings) {
            $fields = [];

            foreach (array_slice($sourceFindings, 0, 10) as $finding) {
                $severityValue = $finding->severity->value;
                $severity = ucfirst($severityValue);
                $severityEmoji = match($severityValue) {
                    'critical' => '🔴',
                    'high' => '🟠',
                    'medium', 'moderate' => '🟡',
                    'low' => '🟢',
                    default => '⚪'
                };

                $value = $finding->title;
                $cve = $finding->cve;
                if ($cve) {
                    $value .= sprintf("\n[CVE: %s](https://www.cve.org/CVERecord?id=%s)", $cve, $cve);
                }

                $package = $finding->package;

                $fields[] = [
                    'name' => sprintf('%s %s - %s', $severityEmoji, $severity, $package),
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

            $appNameConfig = config('warden.app_name', 'Application');
            $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';

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
     * @param array<int, array<string, mixed>> $abandonedPackages
     * @return array<string, mixed>
     */
    protected function buildAbandonedPackagesEmbed(array $abandonedPackages): array
    {
        $fields = [];
        
        foreach (array_slice($abandonedPackages, 0, 20) as $package) {
            $replacement = isset($package['replacement']) && is_string($package['replacement'])
                ? $package['replacement']
                : null;
            $value = $replacement
                ? sprintf('Recommended: `%s`', $replacement)
                : 'No replacement suggested';

            $packageName = is_string($package['package'] ?? null) ? $package['package'] : 'unknown';

            $fields[] = [
                'name' => (string) $packageName,
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
        
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        
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

    /**
     * @param array<int, Finding> $findings
     */
    protected function getSeverityColor(array $findings): int
    {
        $hasCritical = false;
        $hasHigh = false;
        $hasMedium = false;

        foreach ($findings as $finding) {
            switch ($finding->severity->value) {
                case 'critical':
                    $hasCritical = true;
                    break;
                case 'high':
                    $hasHigh = true;
                    break;
                case 'medium':
                case 'moderate':
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