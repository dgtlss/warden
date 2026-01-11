<?php

namespace Dgtlss\Warden\Exceptions;

/**
 * Exception thrown when a notification fails to send.
 */
class NotificationException extends WardenException
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        public readonly ?string $channelName = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Create an exception for a specific channel failure.
     */
    public static function forChannel(string $channelName, string $reason, ?\Throwable $previous = null): self
    {
        return new self(
            message: sprintf('Notification channel "%s" failed: %s', $channelName, $reason),
            previous: $previous,
            channelName: $channelName,
        );
    }

    /**
     * Create an exception for channel not configured.
     */
    public static function notConfigured(string $channelName): self
    {
        return new self(
            message: sprintf('Notification channel "%s" is not properly configured', $channelName),
            channelName: $channelName,
        );
    }
}
