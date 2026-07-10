<?php

declare(strict_types=1);

namespace Dgtlss\Warden\ValueObjects;

use JsonSerializable;

final readonly class AuditError implements JsonSerializable
{
    public function __construct(
        public string $audit,
        public string $code,
        public string $message,
    ) {
    }

    /** @return array{audit: string, code: string, message: string} */
    public function jsonSerialize(): array
    {
        return ['audit' => $this->audit, 'code' => $this->code, 'message' => $this->message];
    }
}
