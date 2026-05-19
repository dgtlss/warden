<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Data\CommandResult;
use Symfony\Component\Process\Process;

class ProcessRunner
{
    /**
     * @param array<int, string> $command
     */
    public function run(array $command, ?string $workingDirectory = null, ?int $timeout = null): CommandResult
    {
        $process = new Process($command, $workingDirectory ?? base_path());
        $process->setTimeout($timeout);
        $process->run();

        return new CommandResult(
            command: $command,
            exitCode: $process->getExitCode() ?? 1,
            stdout: $process->getOutput(),
            stderr: $process->getErrorOutput(),
        );
    }

    public function commandExists(string $binary): bool
    {
        $result = $this->run(['which', $binary], timeout: 15);

        return $result->isSuccessful();
    }
}
