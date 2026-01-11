<?php

namespace Dgtlss\Warden\Exceptions;

/**
 * Exception thrown when an audit operation exceeds the timeout limit.
 */
class AuditTimeoutException extends AuditException
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        ?string $auditName = null,
        public readonly ?int $timeoutSeconds = null,
    ) {
        parent::__construct($message, $code, $previous, $auditName);
    }

    /**
     * Create a timeout exception for a specific audit.
     */
    public static function timeout(string $auditName, int $timeoutSeconds): self
    {
        return new self(
            message: sprintf(
                'Audit "%s" exceeded timeout limit of %d seconds',
                $auditName,
                $timeoutSeconds
            ),
            auditName: $auditName,
            timeoutSeconds: $timeoutSeconds,
        );
    }
}
