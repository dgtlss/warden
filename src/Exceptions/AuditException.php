<?php

namespace Dgtlss\Warden\Exceptions;

/**
 * Exception thrown when an audit operation fails.
 */
class AuditException extends WardenException
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        public readonly ?string $auditName = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Create an exception for a specific audit failure.
     */
    public static function forAudit(string $auditName, string $reason, ?\Throwable $previous = null): self
    {
        return new self(
            message: sprintf('Audit "%s" failed: %s', $auditName, $reason),
            previous: $previous,
            auditName: $auditName,
        );
    }
}
