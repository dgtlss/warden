<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Illuminate\Support\Facades\Http;

class SlackChannel implements NotificationChannel
{
    protected ?string $webhookUrl;

    public function __construct()
    {
        $webhookUrl = config('warden.notifications.slack.webhook_url');
        $this->webhookUrl = is_string($webhookUrl) && $webhookUrl !== '' ? $webhookUrl : null;
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     */
    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $blocks = $this->buildFindingsBlocks($findings);
        
        $appName = (string) config('warden.app_name', 'Application');
        
        if ($this->webhookUrl === null) {
            return;
        }
        
        Http::post($this->webhookUrl, [
            'blocks' => $blocks,
            'text' => sprintf('🚨 [%s] Warden Security Audit: %d vulnerabilities found', $appName, count($findings))
        ]);
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $blocks = $this->buildAbandonedPackagesBlocks($abandonedPackages);
        
        $appName = (string) config('warden.app_name', 'Application');
        
        if ($this->webhookUrl === null) {
            return;
        }
        
        Http::post($this->webhookUrl, [
            'blocks' => $blocks,
            'text' => sprintf('⚠️ [%s] Warden Audit: %d abandoned packages found', $appName, count($abandonedPackages))
        ]);
    }

    public function isConfigured(): bool
    {
        return !in_array($this->webhookUrl, [null, '', '0'], true);
    }

    public function getName(): string
    {
        return 'Slack';
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     * @return array<int, array<string, mixed>>
     */
    protected function buildFindingsBlocks(array $findings): array
    {
        $appName = config('warden.app_name', 'Application');
        
        $blocks = [
            [
                'type' => 'header',
                'text' => [
                    'type' => 'plain_text',
                    'text' => sprintf('🚨 [%s] Warden Security Audit Report', $appName),
                    'emoji' => true
                ]
            ],
            [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => sprintf('*%d vulnerabilities found*', count($findings))
                ]
            ],
            [
                'type' => 'divider'
            ]
        ];

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $severity = isset($finding['severity']) ? (string) $finding['severity'] : 'low';
            $severityEmoji = match($severity) {
                'critical' => '🔴',
                'high' => '🟠',
                'medium' => '🟡',
                'low' => '🟢',
                default => '⚪'
            };

            $title = isset($finding['title']) ? (string) $finding['title'] : 'Security issue';
            $package = isset($finding['package']) ? (string) $finding['package'] : 'unknown';
            $source = isset($finding['source']) ? (string) $finding['source'] : 'unknown';
            $cve = isset($finding['cve']) && is_string($finding['cve']) ? $finding['cve'] : null;

            $blocks[] = [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => sprintf(
                        "%s *%s* - %s\n*Package:* `%s`\n*Source:* %s",
                        $severityEmoji,
                        ucfirst($severity),
                        $title,
                        $package,
                        $source
                    )
                ]
            ];

            if ($cve) {
                $blocks[] = [
                    'type' => 'context',
                    'elements' => [
                        [
                            'type' => 'mrkdwn',
                            'text' => sprintf(
                                '*CVE:* <%s|%s>',
                                'https://www.cve.org/CVERecord?id=' . $cve,
                                $cve
                            )
                        ]
                    ]
                ];
            }
        }

        return $blocks;
    }

    /**
     * @param array<int, array<string, mixed>> $abandonedPackages
     * @return array<int, array<string, mixed>>
     */
    protected function buildAbandonedPackagesBlocks(array $abandonedPackages): array
    {
        $appName = config('warden.app_name', 'Application');
        
        $blocks = [
            [
                'type' => 'header',
                'text' => [
                    'type' => 'plain_text',
                    'text' => sprintf('⚠️ [%s] Abandoned Packages Found', $appName),
                    'emoji' => true
                ]
            ],
            [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => sprintf('*%d abandoned packages detected*', count($abandonedPackages))
                ]
            ],
            [
                'type' => 'divider'
            ]
        ];

        foreach ($abandonedPackages as $abandonedPackage) {
            if (!is_array($abandonedPackage)) {
                continue;
            }

            $package = isset($abandonedPackage['package']) ? (string) $abandonedPackage['package'] : 'unknown';
            $replacement = isset($abandonedPackage['replacement']) && is_string($abandonedPackage['replacement'])
                ? $abandonedPackage['replacement']
                : null;

            $text = sprintf('• `%s`', $package);
            if ($replacement) {
                $text .= sprintf(' → Recommended: `%s`', $replacement);
            }

            $blocks[] = [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => $text
                ]
            ];
        }

        return $blocks;
    }
} 