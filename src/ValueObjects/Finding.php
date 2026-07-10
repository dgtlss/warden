<?php

declare(strict_types=1);

namespace Dgtlss\Warden\ValueObjects;

use Dgtlss\Warden\Enums\Severity;
use InvalidArgumentException;
use JsonSerializable;

final readonly class Finding implements JsonSerializable
{
    /** @param array<string, scalar|null> $metadata */
    public function __construct(
        public string $id,
        public string $source,
        public string $title,
        public Severity $severity,
        public string $description,
        public ?string $remediation = null,
        public ?string $package = null,
        public ?string $reference = null,
        public ?string $path = null,
        public ?int $line = null,
        public bool $blocking = true,
        public array $metadata = [],
        public ?string $identity = null,
    ) {
        if ($this->id === '' || $this->source === '' || $this->title === '' || $this->description === '') {
            throw new InvalidArgumentException('A finding requires a non-empty ID, source, title, and description.');
        }

        if ($this->line !== null && $this->line < 1) {
            throw new InvalidArgumentException('A finding line number must be positive.');
        }

        if ($this->identity === '') {
            throw new InvalidArgumentException('A finding identity cannot be empty.');
        }
    }

    public function fingerprint(): string
    {
        return hash('sha256', implode('|', [
            $this->id,
            $this->package ?? '',
            $this->reference ?? '',
            $this->path ?? '',
            $this->identity ?? (string) ($this->line ?? ''),
        ]));
    }

    public function withBlocking(bool $blocking): self
    {
        return new self(
            $this->id,
            $this->source,
            $this->title,
            $this->severity,
            $this->description,
            $this->remediation,
            $this->package,
            $this->reference,
            $this->path,
            $this->line,
            $blocking,
            $this->metadata,
            $this->identity,
        );
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return array_filter([
            'id' => $this->id,
            'fingerprint' => $this->fingerprint(),
            'source' => $this->source,
            'title' => $this->title,
            'severity' => $this->severity->value,
            'description' => $this->description,
            'remediation' => $this->remediation,
            'package' => $this->package,
            'reference' => $this->reference,
            'location' => $this->path === null ? null : array_filter([
                'path' => $this->path,
                'line' => $this->line,
            ], static fn (mixed $value): bool => $value !== null),
            'blocking' => $this->blocking,
            'metadata' => $this->metadata === [] ? null : $this->metadata,
        ], static fn (mixed $value): bool => $value !== null);
    }
}
