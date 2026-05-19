<?php

namespace Dgtlss\Warden\Data;

class ResolutionPlanItem
{
    /**
     * @param array<int, string> $ruleIds
     * @param array<int, array{command: array<int, string>, display: string}> $commands
     * @param array<int, string> $expectedFiles
     * @param array<int, string> $verificationSteps
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public readonly string $id,
        public readonly string $source,
        public readonly string $package,
        public readonly string $title,
        public readonly array $ruleIds,
        public readonly array $commands,
        public readonly array $expectedFiles,
        public readonly string $riskLevel,
        public readonly bool $requiresNetwork,
        public readonly array $verificationSteps,
        public readonly string $strategy,
        public readonly bool $actionable = true,
        public readonly ?string $reason = null,
        public readonly array $metadata = [],
    ) {
    }

    public function canApply(bool $allowMajor): bool
    {
        if (!$this->actionable) {
            return false;
        }

        if ($this->riskLevel === 'high-risk' && !$allowMajor) {
            return false;
        }

        return true;
    }

    public function isHighRisk(): bool
    {
        return $this->riskLevel === 'high-risk';
    }

    /**
     * @return array<int, string>
     */
    public function displayCommands(): array
    {
        return array_map(
            static fn (array $command): string => $command['display'],
            $this->commands
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'source' => $this->source,
            'package' => $this->package,
            'title' => $this->title,
            'rule_ids' => $this->ruleIds,
            'commands' => $this->displayCommands(),
            'expected_files' => $this->expectedFiles,
            'risk_level' => $this->riskLevel,
            'requires_network' => $this->requiresNetwork,
            'verification_steps' => $this->verificationSteps,
            'strategy' => $this->strategy,
            'actionable' => $this->actionable,
            'reason' => $this->reason,
            'metadata' => $this->metadata,
        ];
    }
}
