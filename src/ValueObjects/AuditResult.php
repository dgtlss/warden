<?php

declare(strict_types=1);

namespace Dgtlss\Warden\ValueObjects;

use JsonSerializable;

final readonly class AuditResult implements JsonSerializable
{
    /**
     * @param list<Finding> $findings
     * @param list<AuditError> $errors
     */
    public function __construct(
        public string $audit,
        public array $findings = [],
        public array $errors = [],
        public float $durationMs = 0.0,
    ) {
    }

    /** @param list<Finding> $findings */
    public static function complete(string $audit, array $findings = []): self
    {
        return new self($audit, $findings);
    }

    public static function failed(string $audit, string $code, string $message): self
    {
        return new self($audit, [], [new AuditError($audit, $code, $message)]);
    }

    public function withDuration(float $durationMs): self
    {
        return new self($this->audit, $this->findings, $this->errors, $durationMs);
    }

    /** @param list<Finding> $findings */
    public function withFindings(array $findings): self
    {
        return new self($this->audit, $findings, $this->errors, $this->durationMs);
    }

    public function succeeded(): bool
    {
        return $this->errors === [];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'id' => $this->audit,
            'status' => $this->succeeded() ? 'completed' : 'failed',
            'duration_ms' => round($this->durationMs, 1),
            'findings' => count($this->findings),
            'errors' => $this->errors,
        ];
    }
}
