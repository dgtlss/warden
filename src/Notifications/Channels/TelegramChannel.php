<?php

namespace Dgtlss\Warden\Notifications\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Http;

class TelegramChannel implements NotificationChannel
{
    protected ?string $botToken;
    protected ?string $chatId;

    public function __construct()
    {
        $botToken = config('warden.notifications.telegram.bot_token');
        $this->botToken = is_string($botToken) && $botToken !== '' ? $botToken : null;

        $chatId = config('warden.notifications.telegram.chat_id');
        $this->chatId = is_string($chatId) && $chatId !== '' ? $chatId : null;
    }

    /**
     * @param array<int, Finding> $findings
     */
    public function send(array $findings): void
    {
        if (!$this->isConfigured()) {
            return;
        }

        $message = $this->formatMessage($findings);

        if ($this->botToken === null || $this->chatId === null) {
            return;
        }

        Http::post("https://api.telegram.org/bot{$this->botToken}/sendMessage", [
            'chat_id' => $this->chatId,
            'text' => $message,
            'parse_mode' => 'HTML',
            'disable_web_page_preview' => true,
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

        $message = $this->formatAbandonedPackagesMessage($abandonedPackages);

        if ($this->botToken === null || $this->chatId === null) {
            return;
        }

        Http::post("https://api.telegram.org/bot{$this->botToken}/sendMessage", [
            'chat_id' => $this->chatId,
            'text' => $message,
            'parse_mode' => 'HTML',
            'disable_web_page_preview' => true,
        ]);
    }

    public function isConfigured(): bool
    {
        return $this->botToken !== null && $this->chatId !== null;
    }

    public function getName(): string
    {
        return 'telegram';
    }

    /**
     * Format findings as Telegram message.
     *
     * @param array<int, Finding> $findings
     */
    protected function formatMessage(array $findings): string
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';

        $severityCounts = $this->countBySeverity($findings);

        $message = "🚨 <b>[{$appName}] Warden Security Audit</b>\n\n";
        $message .= "Found <b>" . count($findings) . "</b> vulnerabilities:\n";
        $message .= "🔴 Critical: {$severityCounts['critical']}\n";
        $message .= "🟠 High: {$severityCounts['high']}\n";
        $message .= "🟡 Medium: {$severityCounts['medium']}\n";
        $message .= "🟢 Low: {$severityCounts['low']}\n\n";

        $message .= "<b>Details:</b>\n";
        $limit = min(count($findings), 10);

        for ($i = 0; $i < $limit; $i++) {
            $finding = $findings[$i];
            $emoji = $this->getSeverityEmoji($finding->severity->value);
            $message .= "\n{$emoji} <b>{$finding->package}</b>\n";
            $message .= "   " . htmlspecialchars($finding->title) . "\n";

            if ($finding->cve) {
                $message .= "   CVE: <code>{$finding->cve}</code>\n";
            }
        }

        if (count($findings) > 10) {
            $remaining = count($findings) - 10;
            $message .= "\n... and {$remaining} more\n";
        }

        return $message;
    }

    /**
     * Format abandoned packages message.
     *
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    protected function formatAbandonedPackagesMessage(array $abandonedPackages): string
    {
        $appNameConfig = config('warden.app_name', 'Application');
        $appName = is_string($appNameConfig) ? $appNameConfig : 'Application';

        $message = "⚠️ <b>[{$appName}] Abandoned Packages Alert</b>\n\n";
        $message .= "Found <b>" . count($abandonedPackages) . "</b> abandoned packages:\n\n";

        $limit = min(count($abandonedPackages), 10);

        for ($i = 0; $i < $limit; $i++) {
            $package = $abandonedPackages[$i];
            $name = is_string($package['name'] ?? null) ? $package['name'] : 'Unknown';
            $message .= "📦 <code>{$name}</code>\n";

            if (isset($package['replacement']) && is_string($package['replacement'])) {
                $message .= "   Replacement: {$package['replacement']}\n";
            }

            $message .= "\n";
        }

        if (count($abandonedPackages) > 10) {
            $remaining = count($abandonedPackages) - 10;
            $message .= "... and {$remaining} more\n";
        }

        return $message;
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

    /**
     * Get emoji for severity level.
     */
    protected function getSeverityEmoji(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium', 'moderate' => '🟡',
            'low' => '🟢',
            default => '⚪',
        };
    }
}
