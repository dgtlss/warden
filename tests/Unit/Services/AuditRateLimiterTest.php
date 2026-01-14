<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Dgtlss\Warden\Services\AuditRateLimiter;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\RateLimiter;

class AuditRateLimiterTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        RateLimiter::clear('warden:audit:test-key');
    }

    protected function tearDown(): void
    {
        RateLimiter::clear('warden:audit:test-key');
        parent::tearDown();
    }

    public function testConstructorSetsDefaultValues(): void
    {
        $limiter = new AuditRateLimiter();

        $this->assertEquals(10, $limiter->getMaxAttempts());
        $this->assertEquals(60, $limiter->getDecayMinutes());
    }

    public function testConstructorAcceptsCustomValues(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 5, decayMinutes: 30);

        $this->assertEquals(5, $limiter->getMaxAttempts());
        $this->assertEquals(30, $limiter->getDecayMinutes());
    }

    public function testFromConfigCreatesInstanceWithConfigValues(): void
    {
        config(['warden.rate_limit.max_attempts' => 15]);
        config(['warden.rate_limit.decay_minutes' => 120]);

        $limiter = AuditRateLimiter::fromConfig();

        $this->assertEquals(15, $limiter->getMaxAttempts());
        $this->assertEquals(120, $limiter->getDecayMinutes());
    }

    public function testIsEnabledReturnsFalseByDefault(): void
    {
        config(['warden.rate_limit.enabled' => false]);

        $limiter = new AuditRateLimiter();

        $this->assertFalse($limiter->isEnabled());
    }

    public function testIsEnabledReturnsTrueWhenEnabled(): void
    {
        config(['warden.rate_limit.enabled' => true]);

        $limiter = new AuditRateLimiter();

        $this->assertTrue($limiter->isEnabled());
    }

    public function testAttemptReturnsTrueWhenUnderLimit(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 5);

        $result = $limiter->attempt('test-key');

        $this->assertTrue($result);
    }

    public function testAttemptReturnsFalseWhenOverLimit(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 2);

        $limiter->attempt('test-key');
        $limiter->attempt('test-key');
        $result = $limiter->attempt('test-key');

        $this->assertFalse($result);
    }

    public function testTooManyAttemptsReturnsFalseInitially(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 5);

        $this->assertFalse($limiter->tooManyAttempts('test-key'));
    }

    public function testTooManyAttemptsReturnsTrueAfterExceedingLimit(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 2);

        $limiter->hit('test-key');
        $limiter->hit('test-key');

        $this->assertTrue($limiter->tooManyAttempts('test-key'));
    }

    public function testHitRecordsAttempt(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 5);

        $this->assertEquals(0, $limiter->attempts('test-key'));

        $limiter->hit('test-key');

        $this->assertEquals(1, $limiter->attempts('test-key'));
    }

    public function testRemainingAttemptsReturnsCorrectCount(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 5);

        $this->assertEquals(5, $limiter->remainingAttempts('test-key'));

        $limiter->hit('test-key');
        $limiter->hit('test-key');

        $this->assertEquals(3, $limiter->remainingAttempts('test-key'));
    }

    public function testClearResetsAttempts(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 5);

        $limiter->hit('test-key');
        $limiter->hit('test-key');
        $limiter->clear('test-key');

        $this->assertEquals(5, $limiter->remainingAttempts('test-key'));
    }

    public function testGetContextKeyReturnsCliKeyInConsole(): void
    {
        $limiter = new AuditRateLimiter();

        $key = $limiter->getContextKey();

        $this->assertStringStartsWith('cli:', $key);
    }

    public function testAttemptsReturnsZeroInitially(): void
    {
        $limiter = new AuditRateLimiter();

        $this->assertEquals(0, $limiter->attempts('test-key'));
    }

    public function testMultipleKeysAreIndependent(): void
    {
        $limiter = new AuditRateLimiter(maxAttempts: 2);

        $limiter->hit('key1');
        $limiter->hit('key1');

        $this->assertTrue($limiter->tooManyAttempts('key1'));
        $this->assertFalse($limiter->tooManyAttempts('key2'));
    }
}
