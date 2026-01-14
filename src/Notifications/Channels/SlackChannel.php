<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\Notifications\Channels\Concerns\SignsWebhooks;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Http;

class SlackChannel implements NotificationChannel
{
    use SignsWebhooks;

    protected ?string $webhookUrl;

    public function __construct()
    {
        $webhookUrl = config('warden.notifications.slack.webhook_url');
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

        $blocks = $this->buildFindingsBlocks($findings);

        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';

        if ($this->webhookUrl === null) {
            return;
        }

        $payload = [
            'blocks' => $blocks,
            'text' => sprintf('🚨 [%s] Warden Security Audit: %d vulnerabilities found', $appName, count($findings)),
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

        $blocks = $this->buildAbandonedPackagesBlocks($abandonedPackages);

        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';

        if ($this->webhookUrl === null) {
            return;
        }

        $payload = [
            'blocks' => $blocks,
            'text' => sprintf('⚠️ [%s] Warden Audit: %d abandoned packages found', $appName, count($abandonedPackages)),
        ];

        $this->sendSignedPost($this->webhookUrl, $payload);
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
     * @param array<int, Finding> $findings
     * @return array<int, array<string, mixed>>
     */
    protected function buildFindingsBlocks(array $findings): array
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        
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
            $severity = $finding->severity->value;
            /** @var string $severityEmoji */
            $severityEmoji = match($severity) {
                'critical' => '🔴',
                'high' => '🟠',
                'medium', 'moderate' => '🟡',
                'low' => '🟢',
                default => '⚪'
            };

            $title = (string) $finding->title;
            $package = (string) $finding->package;
            $source = (string) $finding->source;
            $cve = $finding->cve;

            $blocks[] = [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => sprintf(
                        "%s *%s* - %s\n*Package:* `%s`\n*Source:* %s",
                        (string) $severityEmoji,
                        ucfirst((string) $severity),
                        (string) $title,
                        (string) $package,
                        (string) $source
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
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';
        
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
            $packageName = is_string($abandonedPackage['package'] ?? null) ? $abandonedPackage['package'] : 'unknown';
            $replacement = isset($abandonedPackage['replacement']) && is_string($abandonedPackage['replacement'])
                ? $abandonedPackage['replacement']
                : null;

            $text = sprintf('• `%s`', $packageName);
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