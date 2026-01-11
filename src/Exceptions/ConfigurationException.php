<?php

namespace Dgtlss\Warden\Exceptions;

/**
 * Exception thrown when there's a configuration error.
 */
class ConfigurationException extends WardenException
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        public readonly ?string $configKey = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Create an exception for a missing configuration value.
     */
    public static function missingKey(string $key): self
    {
        return new self(
            message: sprintf('Required configuration key "%s" is missing or empty', $key),
            configKey: $key,
        );
    }

    /**
     * Create an exception for an invalid configuration value.
     */
    public static function invalidValue(string $key, string $reason): self
    {
        return new self(
            message: sprintf('Configuration key "%s" has an invalid value: %s', $key, $reason),
            configKey: $key,
        );
    }
}
