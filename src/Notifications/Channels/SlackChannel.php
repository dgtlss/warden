<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Illuminate\Support\Facades\Http;

class SlackChannel implements NotificationChannel
{
    protected ?string $webhookUrl;

    public function __construct()
    {
        $this->webhookUrl = config('warden.notifications.slack.webhook_url');
    }

    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $blocks = $this->buildFindingsBlocks($findings);
        
        $appName = config('warden.app_name', 'Application');
        
        Http::post($this->webhookUrl, [
            'blocks' => $blocks,
            'text' => sprintf('🚨 [%s] Warden Security Audit: %d vulnerabilities found', $appName, count($findings))
        ]);
    }

    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $blocks = $this->buildAbandonedPackagesBlocks($abandonedPackages);
        
        $appName = config('warden.app_name', 'Application');
        
        Http::post($this->webhookUrl, [
            'blocks' => $blocks,
            'text' => sprintf('⚠️ [%s] Warden Audit: %d abandoned packages found', $appName, count($abandonedPackages))
        ]);
    }

    public function isConfigured(): bool
    {
        return !empty($this->webhookUrl);
    }

    public function getName(): string
    {
        return 'Slack';
    }

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
            $severityEmoji = match($finding['severity']) {
                'critical' => '🔴',
                'high' => '🟠',
                'medium' => '🟡',
                'low' => '🟢',
                default => '⚪'
            };

            $blocks[] = [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => sprintf(
                        "%s *%s* - %s\n*Package:* `%s`\n*Source:* %s",
                        $severityEmoji,
                        ucfirst($finding['severity']),
                        $finding['title'],
                        $finding['package'],
                        $finding['source']
                    )
                ]
            ];

            if (!empty($finding['cve'])) {
                $blocks[] = [
                    'type' => 'context',
                    'elements' => [
                        [
                            'type' => 'mrkdwn',
                            'text' => sprintf(
                                '*CVE:* <%s|%s>',
                                "https://www.cve.org/CVERecord?id={$finding['cve']}",
                                $finding['cve']
                            )
                        ]
                    ]
                ];
            }
        }

        return $blocks;
    }

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

        foreach ($abandonedPackages as $package) {
            $text = sprintf('• `%s`', $package['package']);
            if (!empty($package['replacement'])) {
                $text .= sprintf(' → Recommended: `%s`', $package['replacement']);
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