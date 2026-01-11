<?php

namespace Dgtlss\Warden\ValueObjects;

use Dgtlss\Warden\Enums\Severity;

/**
 * Immutable value object representing a security finding.
 */
final readonly class Finding
{
    public function __construct(
        public string $source,
        public string $package,
        public string $title,
        public Severity $severity,
        public ?string $cve = null,
        public ?string $affectedVersions = null,
        public ?string $error = null,
    ) {
    }

    /**
     * Create a Finding from an array.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            source: $data['source'] ?? 'unknown',
            package: $data['package'] ?? 'unknown',
            title: $data['title'] ?? 'Unknown vulnerability',
            severity: isset($data['severity']) && $data['severity'] instanceof Severity
                ? $data['severity']
                : Severity::fromString($data['severity'] ?? 'unknown'),
            cve: $data['cve'] ?? null,
            affectedVersions: $data['affected_versions'] ?? null,
            error: $data['error'] ?? null,
        );
    }

    /**
     * Convert the Finding to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $array = [
            'source' => $this->source,
            'package' => $this->package,
            'title' => $this->title,
            'severity' => $this->severity->value,
        ];

        if ($this->cve !== null) {
            $array['cve'] = $this->cve;
        }

        if ($this->affectedVersions !== null) {
            $array['affected_versions'] = $this->affectedVersions;
        }

        if ($this->error !== null) {
            $array['error'] = $this->error;
        }

        return $array;
    }

    /**
     * Check if this is a critical finding.
     */
    public function isCritical(): bool
    {
        return $this->severity === Severity::CRITICAL;
    }

    /**
     * Check if this is a high severity finding.
     */
    public function isHigh(): bool
    {
        return $this->severity === Severity::HIGH;
    }

    /**
     * Check if this finding represents an error.
     */
    public function isError(): bool
    {
        return $this->severity === Severity::ERROR || $this->error !== null;
    }

    /**
     * Get a human-readable summary of the finding.
     */
    public function summary(): string
    {
        return sprintf(
            '[%s] %s: %s (%s)',
            strtoupper($this->severity->value),
            $this->package,
            $this->title,
            $this->source
        );
    }

    /**
     * Create a new Finding with modified values.
     */
    public function with(
        ?string $source = null,
        ?string $package = null,
        ?string $title = null,
        ?Severity $severity = null,
        ?string $cve = null,
        ?string $affectedVersions = null,
        ?string $error = null,
    ): self {
        return new self(
            source: $source ?? $this->source,
            package: $package ?? $this->package,
            title: $title ?? $this->title,
            severity: $severity ?? $this->severity,
            cve: $cve ?? $this->cve,
            affectedVersions: $affectedVersions ?? $this->affectedVersions,
            error: $error ?? $this->error,
        );
    }
}
