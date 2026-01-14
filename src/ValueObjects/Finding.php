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
        public ?Remediation $remediation = null,
    ) {
    }

    /**
     * Create a Finding from an array.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $remediation = null;
        if (isset($data['remediation'])) {
            if ($data['remediation'] instanceof Remediation) {
                $remediation = $data['remediation'];
            } elseif (is_array($data['remediation'])) {
                /** @var array<string, mixed> $remediationData */
                $remediationData = $data['remediation'];
                $remediation = Remediation::fromArray($remediationData);
            }
        }

        return new self(
            source: is_string($data['source'] ?? null) ? $data['source'] : 'unknown',
            package: is_string($data['package'] ?? null) ? $data['package'] : 'unknown',
            title: is_string($data['title'] ?? null) ? $data['title'] : 'Unknown vulnerability',
            severity: isset($data['severity']) && $data['severity'] instanceof Severity
                ? $data['severity']
                : Severity::fromString(is_string($data['severity'] ?? null) ? $data['severity'] : 'unknown'),
            cve: is_string($data['cve'] ?? null) ? $data['cve'] : null,
            affectedVersions: is_string($data['affected_versions'] ?? null) ? $data['affected_versions'] : null,
            error: is_string($data['error'] ?? null) ? $data['error'] : null,
            remediation: $remediation,
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

        if ($this->remediation !== null) {
            $array['remediation'] = $this->remediation->toArray();
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
     * Check if this finding has remediation suggestions.
     */
    public function hasRemediation(): bool
    {
        return $this->remediation !== null;
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
        ?Remediation $remediation = null,
    ): self {
        return new self(
            source: $source ?? $this->source,
            package: $package ?? $this->package,
            title: $title ?? $this->title,
            severity: $severity ?? $this->severity,
            cve: $cve ?? $this->cve,
            affectedVersions: $affectedVersions ?? $this->affectedVersions,
            error: $error ?? $this->error,
            remediation: $remediation ?? $this->remediation,
        );
    }

    /**
     * Create a new Finding with remediation suggestions.
     */
    public function withRemediation(Remediation $remediation): self
    {
        return new self(
            source: $this->source,
            package: $this->package,
            title: $this->title,
            severity: $this->severity,
            cve: $this->cve,
            affectedVersions: $this->affectedVersions,
            error: $this->error,
            remediation: $remediation,
        );
    }
}
