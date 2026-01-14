<?php

namespace Dgtlss\Warden\ValueObjects;

/**
 * Immutable value object representing remediation suggestions for a security finding.
 */
final readonly class Remediation
{
    /**
     * @param string $description Human-readable description of how to fix the issue
     * @param array<int, string> $commands Shell commands to run to fix the issue
     * @param array<int, string> $manualSteps Manual steps if commands aren't sufficient
     * @param array<int, string> $links Reference URLs (security advisories, documentation)
     * @param string $priority Suggested fix priority (immediate, high, medium, low)
     */
    public function __construct(
        public string $description,
        public array $commands = [],
        public array $manualSteps = [],
        public array $links = [],
        public string $priority = 'medium',
    ) {
    }

    /**
     * Create a Remediation from an array.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        /** @var array<int, string> $commands */
        $commands = is_array($data['commands'] ?? null)
            ? array_values(array_filter($data['commands'], 'is_string'))
            : [];

        /** @var array<int, string> $manualSteps */
        $manualSteps = is_array($data['manual_steps'] ?? null)
            ? array_values(array_filter($data['manual_steps'], 'is_string'))
            : [];

        /** @var array<int, string> $links */
        $links = is_array($data['links'] ?? null)
            ? array_values(array_filter($data['links'], 'is_string'))
            : [];

        return new self(
            description: is_string($data['description'] ?? null) ? $data['description'] : 'No remediation available',
            commands: $commands,
            manualSteps: $manualSteps,
            links: $links,
            priority: is_string($data['priority'] ?? null) ? $data['priority'] : 'medium',
        );
    }

    /**
     * Convert the Remediation to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $array = [
            'description' => $this->description,
            'priority' => $this->priority,
        ];

        if (!empty($this->commands)) {
            $array['commands'] = $this->commands;
        }

        if (!empty($this->manualSteps)) {
            $array['manual_steps'] = $this->manualSteps;
        }

        if (!empty($this->links)) {
            $array['links'] = $this->links;
        }

        return $array;
    }

    /**
     * Check if this remediation has executable commands.
     */
    public function hasCommands(): bool
    {
        return !empty($this->commands);
    }

    /**
     * Check if this remediation has manual steps.
     */
    public function hasManualSteps(): bool
    {
        return !empty($this->manualSteps);
    }

    /**
     * Check if this remediation has reference links.
     */
    public function hasLinks(): bool
    {
        return !empty($this->links);
    }

    /**
     * Check if the priority is immediate.
     */
    public function isImmediate(): bool
    {
        return $this->priority === 'immediate';
    }

    /**
     * Check if the priority is high or immediate.
     */
    public function isHighPriority(): bool
    {
        return in_array($this->priority, ['immediate', 'high'], true);
    }

    /**
     * Get a human-readable summary of the remediation.
     */
    public function summary(): string
    {
        $parts = [sprintf('[%s] %s', strtoupper($this->priority), $this->description)];

        if ($this->hasCommands()) {
            $parts[] = sprintf('Commands: %s', implode('; ', $this->commands));
        }

        return implode(' | ', $parts);
    }

    /**
     * Create a new Remediation with modified values.
     *
     * @param array<int, string>|null $commands
     * @param array<int, string>|null $manualSteps
     * @param array<int, string>|null $links
     */
    public function with(
        ?string $description = null,
        ?array $commands = null,
        ?array $manualSteps = null,
        ?array $links = null,
        ?string $priority = null,
    ): self {
        return new self(
            description: $description ?? $this->description,
            commands: $commands ?? $this->commands,
            manualSteps: $manualSteps ?? $this->manualSteps,
            links: $links ?? $this->links,
            priority: $priority ?? $this->priority,
        );
    }
}
