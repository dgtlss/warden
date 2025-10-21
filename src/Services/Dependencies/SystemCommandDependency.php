<?php

namespace Dgtlss\Warden\Services\Dependencies;

use Dgtlss\Warden\Abstracts\AbstractAuditDependency;
use Symfony\Component\Process\Process;

class SystemCommandDependency extends AbstractAuditDependency
{
    protected string $command;
    protected array $checkArgs;
    protected ?string $installCommand;

    public function __construct(string $command, array $checkArgs = [], ?string $installCommand = null, int $priority = 100)
    {
        parent::__construct("command-{$command}", 'system-command', $priority);
        $this->command = $command;
        $this->checkArgs = $checkArgs;
        $this->installCommand = $installCommand;
    }

    /**
     * Check if the dependency is satisfied.
     *
     * @return bool
     */
    public function isSatisfied(): bool
    {
        $windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $testCommand = $windows ? 'where' : 'which';
        
        $process = new Process(array_merge([$testCommand], [$this->command]));
        $process->run();
        
        return $process->isSuccessful();
    }

    /**
     * Get the reason why the dependency is not satisfied.
     *
     * @return string|null
     */
    public function getUnsatisfiedReason(): ?string
    {
        if ($this->isSatisfied()) {
            return null;
        }

        $message = "System command '{$this->command}' is not available in PATH";
        
        if ($this->installCommand) {
            $message .= ". Install with: {$this->installCommand}";
        }

        return $message;
    }

    /**
     * Attempt to resolve the dependency.
     *
     * @return bool
     */
    public function resolve(): bool
    {
        // System commands cannot be automatically resolved at runtime
        return false;
    }

    /**
     * Get configuration options for this dependency.
     *
     * @return array
     */
    public function getConfigOptions(): array
    {
        return [
            'command' => [
                'type' => 'string',
                'description' => 'The command to check for',
                'required' => true,
            ],
            'check_args' => [
                'type' => 'array',
                'description' => 'Additional arguments for command verification',
                'default' => [],
            ],
            'install_command' => [
                'type' => 'string',
                'description' => 'Command to install this dependency',
                'required' => false,
            ]
        ];
    }
}