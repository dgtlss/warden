<?php

namespace Dgtlss\Warden\Notifications\Channels\Concerns;

use Dgtlss\Warden\Services\WebhookSignatureService;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;

/**
 * Trait for adding webhook signature support to notification channels.
 */
trait SignsWebhooks
{
    /**
     * Check if webhook signing is enabled.
     */
    protected function isSigningEnabled(): bool
    {
        /** @var bool $enabled */
        $enabled = config('warden.webhook_security.enabled', false);

        return $enabled;
    }

    /**
     * Get the webhook secret for signing.
     */
    protected function getWebhookSecret(): ?string
    {
        $secret = config('warden.webhook_security.secret');

        return is_string($secret) && $secret !== '' ? $secret : null;
    }

    /**
     * Create an HTTP client with optional signature headers.
     *
     * @param array<string, mixed> $payload
     */
    protected function createSignedRequest(array $payload): PendingRequest
    {
        $request = Http::asJson();

        if ($this->isSigningEnabled()) {
            $secret = $this->getWebhookSecret();

            if ($secret !== null) {
                $signatureService = new WebhookSignatureService();
                $headers = $signatureService->generateHeaders($payload, $secret);

                /** @var array<string, string> $stringHeaders */
                $stringHeaders = [];
                foreach ($headers as $key => $value) {
                    $stringHeaders[$key] = (string) $value;
                }

                $request = $request->withHeaders($stringHeaders);
            }
        }

        return $request;
    }

    /**
     * Send a signed POST request.
     *
     * @param array<string, mixed> $payload
     */
    protected function sendSignedPost(string $url, array $payload): \Illuminate\Http\Client\Response
    {
        return $this->createSignedRequest($payload)->post($url, $payload);
    }
}
