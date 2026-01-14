<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Dgtlss\Warden\Services\WebhookSignatureService;
use Dgtlss\Warden\Tests\TestCase;

class WebhookSignatureServiceTest extends TestCase
{
    private WebhookSignatureService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new WebhookSignatureService();
    }

    public function testSignReturnsValidHash(): void
    {
        $payload = ['message' => 'test', 'count' => 5];
        $secret = 'test-secret-key';

        $signature = $this->service->sign($payload, $secret);

        $this->assertIsString($signature);
        $this->assertEquals(64, strlen($signature)); // SHA256 produces 64 hex characters
    }

    public function testSignProducesDifferentHashesForDifferentPayloads(): void
    {
        $secret = 'test-secret-key';
        $payload1 = ['message' => 'test1'];
        $payload2 = ['message' => 'test2'];

        $signature1 = $this->service->sign($payload1, $secret);
        $signature2 = $this->service->sign($payload2, $secret);

        $this->assertNotEquals($signature1, $signature2);
    }

    public function testSignProducesDifferentHashesForDifferentSecrets(): void
    {
        $payload = ['message' => 'test'];

        $signature1 = $this->service->sign($payload, 'secret1');
        $signature2 = $this->service->sign($payload, 'secret2');

        $this->assertNotEquals($signature1, $signature2);
    }

    public function testSignProducesSameHashForSameInput(): void
    {
        $payload = ['message' => 'test', 'count' => 5];
        $secret = 'test-secret-key';

        $signature1 = $this->service->sign($payload, $secret);
        $signature2 = $this->service->sign($payload, $secret);

        $this->assertEquals($signature1, $signature2);
    }

    public function testVerifyReturnsTrueForValidSignature(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $signature = $this->service->sign($payload, $secret);
        $isValid = $this->service->verify($payload, $signature, $secret);

        $this->assertTrue($isValid);
    }

    public function testVerifyReturnsFalseForInvalidSignature(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $isValid = $this->service->verify($payload, 'invalid-signature', $secret);

        $this->assertFalse($isValid);
    }

    public function testVerifyReturnsFalseForWrongSecret(): void
    {
        $payload = ['message' => 'test'];
        $signature = $this->service->sign($payload, 'correct-secret');

        $isValid = $this->service->verify($payload, $signature, 'wrong-secret');

        $this->assertFalse($isValid);
    }

    public function testVerifyReturnsFalseForTamperedPayload(): void
    {
        $originalPayload = ['message' => 'test'];
        $tamperedPayload = ['message' => 'tampered'];
        $secret = 'test-secret-key';

        $signature = $this->service->sign($originalPayload, $secret);
        $isValid = $this->service->verify($tamperedPayload, $signature, $secret);

        $this->assertFalse($isValid);
    }

    public function testSignWithTimestampIncludesTimestamp(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $result = $this->service->signWithTimestamp($payload, $secret);

        $this->assertArrayHasKey('signature', $result);
        $this->assertArrayHasKey('timestamp', $result);
        $this->assertIsString($result['signature']);
        $this->assertIsInt($result['timestamp']);
    }

    public function testVerifyWithTimestampReturnsTrueForValidRequest(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $result = $this->service->signWithTimestamp($payload, $secret);
        $isValid = $this->service->verifyWithTimestamp(
            $payload,
            $result['signature'],
            $secret,
            $result['timestamp']
        );

        $this->assertTrue($isValid);
    }

    public function testVerifyWithTimestampReturnsFalseForExpiredTimestamp(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $oldTimestamp = time() - 600; // 10 minutes ago
        $payloadWithTimestamp = array_merge($payload, ['_timestamp' => $oldTimestamp]);
        $signature = $this->service->sign($payloadWithTimestamp, $secret);

        $isValid = $this->service->verifyWithTimestamp(
            $payload,
            $signature,
            $secret,
            $oldTimestamp,
            300 // 5 minute max difference
        );

        $this->assertFalse($isValid);
    }

    public function testGenerateTimestampReturnsCurrentTime(): void
    {
        $before = time();
        $timestamp = $this->service->generateTimestamp();
        $after = time();

        $this->assertGreaterThanOrEqual($before, $timestamp);
        $this->assertLessThanOrEqual($after, $timestamp);
    }

    public function testIsTimestampValidReturnsTrueForRecentTimestamp(): void
    {
        $timestamp = time();

        $this->assertTrue($this->service->isTimestampValid($timestamp));
    }

    public function testIsTimestampValidReturnsFalseForOldTimestamp(): void
    {
        $oldTimestamp = time() - 600; // 10 minutes ago

        $this->assertFalse($this->service->isTimestampValid($oldTimestamp, 300));
    }

    public function testIsTimestampValidReturnsFalseForFutureTimestamp(): void
    {
        $futureTimestamp = time() + 600; // 10 minutes in future

        $this->assertFalse($this->service->isTimestampValid($futureTimestamp, 300));
    }

    public function testGetSignatureHeaderNameReturnsCorrectValue(): void
    {
        $this->assertEquals('X-Warden-Signature', $this->service->getSignatureHeaderName());
    }

    public function testGetTimestampHeaderNameReturnsCorrectValue(): void
    {
        $this->assertEquals('X-Warden-Timestamp', $this->service->getTimestampHeaderName());
    }

    public function testGenerateHeadersReturnsCorrectStructure(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $headers = $this->service->generateHeaders($payload, $secret);

        $this->assertArrayHasKey('X-Warden-Signature', $headers);
        $this->assertArrayHasKey('X-Warden-Timestamp', $headers);
    }

    public function testVerifyHeadersReturnsTrueForValidHeaders(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $headers = $this->service->generateHeaders($payload, $secret);
        $isValid = $this->service->verifyHeaders($payload, $headers, $secret);

        $this->assertTrue($isValid);
    }

    public function testVerifyHeadersReturnsFalseForMissingSignature(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $headers = ['X-Warden-Timestamp' => time()];
        $isValid = $this->service->verifyHeaders($payload, $headers, $secret);

        $this->assertFalse($isValid);
    }

    public function testVerifyHeadersReturnsFalseForMissingTimestamp(): void
    {
        $payload = ['message' => 'test'];
        $secret = 'test-secret-key';

        $headers = ['X-Warden-Signature' => 'some-signature'];
        $isValid = $this->service->verifyHeaders($payload, $headers, $secret);

        $this->assertFalse($isValid);
    }
}
