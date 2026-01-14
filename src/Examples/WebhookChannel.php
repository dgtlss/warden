<?php

namespace Dgtlss\Warden\Examples;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Http;

/**
 * Example notification channel that sends findings to a generic webhook.
 *
 * This demonstrates how to create a custom notification channel for a Warden plugin.
 * It sends a JSON payload to any HTTP endpoint, making it easy to integrate with
 * custom dashboards, logging systems, or third-party services.
 *
 * Configuration:
 * - WARDEN_CUSTOM_WEBHOOK_URL: The endpoint to send notifications to
 * - WARDEN_CUSTOM_WEBHOOK_SECRET: Optional shared secret for authentication
 *
 * @example
 * ```php
 * // In your plugin's channels() method:
 * public function channels(): array
 * {
 *     return [WebhookChannel::class];
 * }
 * ```
 *
 * @example
 * ```env
 * WARDEN_CUSTOM_WEBHOOK_URL=https://your-service.com/api/security-alerts
 * WARDEN_CUSTOM_WEBHOOK_SECRET=your-shared-secret
 * ```
 */
class WebhookChannel implements NotificationChannel
{
    protected ?string $webhookUrl;

    protected ?string $secret;

    public function __construct()
    {
        $webhookUrl = config('warden.custom_webhook.url', env('WARDEN_CUSTOM_WEBHOOK_URL'));
        $this->webhookUrl = is_string($webhookUrl) ? $webhookUrl : null;

        $secret = config('warden.custom_webhook.secret', env('WARDEN_CUSTOM_WEBHOOK_SECRET'));
        $this->secret = is_string($secret) ? $secret : null;
    }

    public function getName(): string
    {
        return 'Custom Webhook';
    }

    public function isConfigured(): bool
    {
        return $this->webhookUrl !== null && $this->webhookUrl !== '';
    }

    /**
     * Send audit findings to the webhook endpoint.
     *
     * @param array<int, Finding> $findings
     */
    public function send(array $findings): void
    {
        if (!$this->isConfigured() || $findings === []) {
            return;
        }

        $payload = $this->buildPayload($findings);
        $this->sendRequest($payload);
    }

    /**
     * Send abandoned packages notification.
     *
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        if (!$this->isConfigured() || $abandonedPackages === []) {
            return;
        }

        $payload = [
            'type' => 'abandoned_packages',
            'app_name' => config('warden.app_name', config('app.name', 'Application')),
            'timestamp' => now()->toIso8601String(),
            'packages' => array_map(function (array $package): array {
                return [
                    'name' => $package['package'] ?? 'unknown',
                    'replacement' => $package['replacement'] ?? null,
                ];
            }, $abandonedPackages),
        ];

        $this->sendRequest($payload);
    }

    /**
     * Build the webhook payload from findings.
     *
     * @param array<int, Finding> $findings
     * @return array<string, mixed>
     */
    protected function buildPayload(array $findings): array
    {
        $severityCounts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
        ];

        $formattedFindings = [];

        foreach ($findings as $finding) {
            $severity = $finding->severity->value;
            if (isset($severityCounts[$severity])) {
                $severityCounts[$severity]++;
            }

            $formattedFindings[] = [
                'source' => $finding->source,
                'package' => $finding->package,
                'title' => $finding->title,
                'severity' => $severity,
                'cve' => $finding->cve,
                'affected_versions' => $finding->affectedVersions,
                'description' => $finding->description,
            ];
        }

        return [
            'type' => 'security_findings',
            'app_name' => config('warden.app_name', config('app.name', 'Application')),
            'timestamp' => now()->toIso8601String(),
            'summary' => [
                'total' => count($findings),
                'critical' => $severityCounts['critical'],
                'high' => $severityCounts['high'],
                'medium' => $severityCounts['medium'],
                'low' => $severityCounts['low'],
            ],
            'findings' => $formattedFindings,
        ];
    }

    /**
     * Send the HTTP request to the webhook.
     *
     * @param array<string, mixed> $payload
     */
    protected function sendRequest(array $payload): void
    {
        $request = Http::timeout(30)
            ->acceptJson();

        if ($this->secret !== null && $this->secret !== '') {
            $request = $request->withHeaders([
                'Authorization' => 'Bearer ' . $this->secret,
                'X-Warden-Signature' => $this->generateSignature($payload),
            ]);
        }

        /** @var string $url */
        $url = $this->webhookUrl;
        $request->post($url, $payload);
    }

    /**
     * Generate HMAC signature for the payload.
     *
     * @param array<string, mixed> $payload
     */
    protected function generateSignature(array $payload): string
    {
        $json = json_encode($payload);
        if ($json === false) {
            $json = '';
        }

        return hash_hmac('sha256', $json, $this->secret ?? '');
    }
}
