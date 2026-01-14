<?php

namespace Dgtlss\Warden\Services;

/**
 * Service for signing and verifying webhook payloads using HMAC-SHA256.
 */
class WebhookSignatureService
{
    /**
     * The algorithm used for signing.
     */
    private const ALGORITHM = 'sha256';

    /**
     * The header name for the signature.
     */
    private const SIGNATURE_HEADER = 'X-Warden-Signature';

    /**
     * The header name for the timestamp.
     */
    private const TIMESTAMP_HEADER = 'X-Warden-Timestamp';

    /**
     * Maximum allowed time difference in seconds for replay attack prevention.
     */
    private const MAX_TIME_DIFFERENCE = 300;

    /**
     * Sign a payload with the given secret.
     *
     * @param array<string, mixed> $payload
     */
    public function sign(array $payload, string $secret): string
    {
        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        return hash_hmac(self::ALGORITHM, $json, $secret);
    }

    /**
     * Sign a payload with timestamp for replay attack prevention.
     *
     * @param array<string, mixed> $payload
     * @return array{signature: string, timestamp: int}
     */
    public function signWithTimestamp(array $payload, string $secret): array
    {
        $timestamp = $this->generateTimestamp();
        $payloadWithTimestamp = array_merge($payload, ['_timestamp' => $timestamp]);
        $signature = $this->sign($payloadWithTimestamp, $secret);

        return [
            'signature' => $signature,
            'timestamp' => $timestamp,
        ];
    }

    /**
     * Verify a signature against a payload.
     *
     * @param array<string, mixed> $payload
     */
    public function verify(array $payload, string $signature, string $secret): bool
    {
        $expectedSignature = $this->sign($payload, $secret);

        return hash_equals($expectedSignature, $signature);
    }

    /**
     * Verify a signature with timestamp check for replay attack prevention.
     *
     * @param array<string, mixed> $payload
     */
    public function verifyWithTimestamp(
        array $payload,
        string $signature,
        string $secret,
        int $timestamp,
        ?int $maxTimeDifference = null
    ): bool {
        $maxDiff = $maxTimeDifference ?? self::MAX_TIME_DIFFERENCE;

        if (!$this->isTimestampValid($timestamp, $maxDiff)) {
            return false;
        }

        $payloadWithTimestamp = array_merge($payload, ['_timestamp' => $timestamp]);

        return $this->verify($payloadWithTimestamp, $signature, $secret);
    }

    /**
     * Generate a current Unix timestamp.
     */
    public function generateTimestamp(): int
    {
        return time();
    }

    /**
     * Check if a timestamp is within the acceptable range.
     */
    public function isTimestampValid(int $timestamp, ?int $maxDifference = null): bool
    {
        $maxDiff = $maxDifference ?? self::MAX_TIME_DIFFERENCE;
        $currentTime = $this->generateTimestamp();

        return abs($currentTime - $timestamp) <= $maxDiff;
    }

    /**
     * Get the signature header name.
     */
    public function getSignatureHeaderName(): string
    {
        return self::SIGNATURE_HEADER;
    }

    /**
     * Get the timestamp header name.
     */
    public function getTimestampHeaderName(): string
    {
        return self::TIMESTAMP_HEADER;
    }

    /**
     * Generate headers for a signed request.
     *
     * @param array<string, mixed> $payload
     * @return array<string, string|int>
     */
    public function generateHeaders(array $payload, string $secret): array
    {
        $result = $this->signWithTimestamp($payload, $secret);

        return [
            self::SIGNATURE_HEADER => $result['signature'],
            self::TIMESTAMP_HEADER => $result['timestamp'],
        ];
    }

    /**
     * Verify headers from an incoming request.
     *
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $headers
     */
    public function verifyHeaders(array $payload, array $headers, string $secret): bool
    {
        $signature = $headers[self::SIGNATURE_HEADER] ?? $headers[strtolower(self::SIGNATURE_HEADER)] ?? null;
        $timestamp = $headers[self::TIMESTAMP_HEADER] ?? $headers[strtolower(self::TIMESTAMP_HEADER)] ?? null;

        if (!is_string($signature) || $timestamp === null) {
            return false;
        }

        $timestampInt = is_numeric($timestamp) ? (int) $timestamp : 0;

        return $this->verifyWithTimestamp($payload, $signature, $secret, $timestampInt);
    }
}
