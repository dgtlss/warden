<?php

namespace Dgtlss\Warden\Data;

class CommandResult
{
    /**
     * @param array<int, string> $command
     */
    public function __construct(
        public readonly array $command,
        public readonly int $exitCode,
        public readonly string $stdout,
        public readonly string $stderr,
    ) {
    }

    public function isSuccessful(): bool
    {
        return $this->exitCode === 0;
    }

    public function displayCommand(): string
    {
        return implode(' ', array_map('escapeshellarg', $this->command));
    }
}
