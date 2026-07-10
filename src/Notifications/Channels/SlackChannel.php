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

    /** @param array<array<string, mixed>> $findings */
    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $blocks = $this->buildFindingsBlocks($findings);
        
        $appName = config('warden.app_name', 'Application');
        
        if ($this->webhookUrl === null) {
            return;
        }
        
        Http::post($this->webhookUrl, [
            'blocks' => $blocks,
            'text' => sprintf('🚨 [%s] Warden Security Audit: %d vulnerabilities found', $appName, count($findings))
        ])->throw();
    }

    /** @param array<array<string, mixed>> $abandonedPackages */
    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $blocks = $this->buildAbandonedPackagesBlocks($abandonedPackages);
        
        $appName = config('warden.app_name', 'Application');
        
        if ($this->webhookUrl === null) {
            return;
        }
        
        Http::post($this->webhookUrl, [
            'blocks' => $blocks,
            'text' => sprintf('⚠️ [%s] Warden Audit: %d abandoned packages found', $appName, count($abandonedPackages))
        ])->throw();
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
     * @param array<array<string, mixed>> $findings
     * @return array<array<string, mixed>>
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
                        $finding['package'] ?? 'application',
                        $finding['source'] ?? 'unknown'
                    )
                ]
            ];

            if (!empty($finding['cve'])) {
                $reference = (string) $finding['cve'];
                $referenceUrl = filter_var($reference, FILTER_VALIDATE_URL)
                    ? $reference
                    : 'https://www.cve.org/CVERecord?id=' . rawurlencode($reference);
                $blocks[] = [
                    'type' => 'context',
                    'elements' => [
                        [
                            'type' => 'mrkdwn',
                            'text' => sprintf(
                                '*Reference:* <%s|%s>',
                                $referenceUrl,
                                $reference
                            )
                        ]
                    ]
                ];
            }
        }

        return $blocks;
    }

    /**
     * @param array<array<string, mixed>> $abandonedPackages
     * @return array<array<string, mixed>>
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
            $text = sprintf('• `%s`', $abandonedPackage['package']);
            if (!empty($abandonedPackage['replacement'])) {
                $text .= sprintf(' → Recommended: `%s`', $abandonedPackage['replacement']);
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
