<?php

namespace Dgtlss\Warden\Tests\Unit\Exceptions;

use Dgtlss\Warden\Exceptions\AuditException;
use Dgtlss\Warden\Exceptions\AuditTimeoutException;
use Dgtlss\Warden\Exceptions\ConfigurationException;
use Dgtlss\Warden\Exceptions\NotificationException;
use Dgtlss\Warden\Exceptions\WardenException;
use Dgtlss\Warden\Tests\TestCase;

class ExceptionsTest extends TestCase
{
    public function testWardenExceptionCanBeCreated(): void
    {
        $exception = new WardenException('Test message');

        $this->assertInstanceOf(WardenException::class, $exception);
        $this->assertEquals('Test message', $exception->getMessage());
    }

    public function testAuditExceptionCanBeCreated(): void
    {
        $exception = new AuditException('Audit failed', 0, null, 'composer');

        $this->assertInstanceOf(AuditException::class, $exception);
        $this->assertInstanceOf(WardenException::class, $exception);
        $this->assertEquals('Audit failed', $exception->getMessage());
        $this->assertEquals('composer', $exception->auditName);
    }

    public function testAuditExceptionForAuditCreatesFormattedMessage(): void
    {
        $exception = AuditException::forAudit('npm', 'Process timeout');

        $this->assertStringContainsString('npm', $exception->getMessage());
        $this->assertStringContainsString('Process timeout', $exception->getMessage());
        $this->assertEquals('npm', $exception->auditName);
    }

    public function testAuditExceptionForAuditWithPreviousException(): void
    {
        $previous = new \RuntimeException('Original error');
        $exception = AuditException::forAudit('composer', 'Failed', $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testAuditTimeoutExceptionExtendsAuditException(): void
    {
        $exception = new AuditTimeoutException();

        $this->assertInstanceOf(AuditTimeoutException::class, $exception);
        $this->assertInstanceOf(AuditException::class, $exception);
        $this->assertInstanceOf(WardenException::class, $exception);
    }

    public function testAuditTimeoutExceptionStoresTimeout(): void
    {
        $exception = new AuditTimeoutException(
            'Timeout',
            0,
            null,
            'composer',
            120
        );

        $this->assertEquals(120, $exception->timeoutSeconds);
        $this->assertEquals('composer', $exception->auditName);
    }

    public function testAuditTimeoutExceptionTimeoutCreatesFormattedMessage(): void
    {
        $exception = AuditTimeoutException::timeout('npm', 60);

        $this->assertStringContainsString('npm', $exception->getMessage());
        $this->assertStringContainsString('60', $exception->getMessage());
        $this->assertStringContainsString('timeout', strtolower($exception->getMessage()));
        $this->assertEquals('npm', $exception->auditName);
        $this->assertEquals(60, $exception->timeoutSeconds);
    }

    public function testConfigurationExceptionCanBeCreated(): void
    {
        $exception = new ConfigurationException('Config error', 0, null, 'warden.cache.enabled');

        $this->assertInstanceOf(ConfigurationException::class, $exception);
        $this->assertInstanceOf(WardenException::class, $exception);
        $this->assertEquals('Config error', $exception->getMessage());
        $this->assertEquals('warden.cache.enabled', $exception->configKey);
    }

    public function testConfigurationExceptionMissingKeyCreatesFormattedMessage(): void
    {
        $exception = ConfigurationException::missingKey('warden.notifications.slack.webhook_url');

        $this->assertStringContainsString('warden.notifications.slack.webhook_url', $exception->getMessage());
        $this->assertStringContainsString('missing', strtolower($exception->getMessage()));
        $this->assertEquals('warden.notifications.slack.webhook_url', $exception->configKey);
    }

    public function testConfigurationExceptionInvalidValueCreatesFormattedMessage(): void
    {
        $exception = ConfigurationException::invalidValue('warden.cache.duration', 'must be positive integer');

        $this->assertStringContainsString('warden.cache.duration', $exception->getMessage());
        $this->assertStringContainsString('must be positive integer', $exception->getMessage());
        $this->assertStringContainsString('invalid', strtolower($exception->getMessage()));
        $this->assertEquals('warden.cache.duration', $exception->configKey);
    }

    public function testNotificationExceptionCanBeCreated(): void
    {
        $exception = new NotificationException('Send failed', 0, null, 'slack');

        $this->assertInstanceOf(NotificationException::class, $exception);
        $this->assertInstanceOf(WardenException::class, $exception);
        $this->assertEquals('Send failed', $exception->getMessage());
        $this->assertEquals('slack', $exception->channelName);
    }

    public function testNotificationExceptionForChannelCreatesFormattedMessage(): void
    {
        $exception = NotificationException::forChannel('discord', 'HTTP 500 error');

        $this->assertStringContainsString('discord', $exception->getMessage());
        $this->assertStringContainsString('HTTP 500 error', $exception->getMessage());
        $this->assertEquals('discord', $exception->channelName);
    }

    public function testNotificationExceptionForChannelWithPreviousException(): void
    {
        $previous = new \RuntimeException('Connection refused');
        $exception = NotificationException::forChannel('teams', 'Failed to connect', $previous);

        $this->assertSame($previous, $exception->getPrevious());
        $this->assertEquals('teams', $exception->channelName);
    }

    public function testNotificationExceptionNotConfiguredCreatesFormattedMessage(): void
    {
        $exception = NotificationException::notConfigured('email');

        $this->assertStringContainsString('email', $exception->getMessage());
        $this->assertStringContainsString('not properly configured', $exception->getMessage());
        $this->assertEquals('email', $exception->channelName);
    }

    public function testExceptionsCanBeThrown(): void
    {
        $this->expectException(WardenException::class);
        throw new WardenException('Test exception');
    }

    public function testExceptionsCanBeCaught(): void
    {
        try {
            throw AuditException::forAudit('test', 'error');
        } catch (WardenException $e) {
            $this->assertInstanceOf(AuditException::class, $e);
            $this->assertEquals('test', $e->auditName);
        }
    }
}
