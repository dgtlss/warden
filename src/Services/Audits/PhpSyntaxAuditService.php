<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;

class PhpSyntaxAuditService extends AbstractAuditService
{
    public function getName(): string
    {
        return 'PHP Syntax';
    }

    public function run(): bool
    {
        $process = $this->getProcess();
        $timeout = config('warden.audits.timeout', 300);
        $process->setTimeout(is_numeric($timeout) ? (float) $timeout : 300.0);
        $process->run();

        // The command's output can be on stdout or stderr, so we combine them.
        $output = $process->getOutput() . $process->getErrorOutput();
        $errors = $this->parseOutput($output);

        foreach ($errors as $error) {
            $filePath = str_replace(base_path() . '/', '', $error['file']);
            $this->addFinding([
                'package' => 'Application Code',
                'title' => 'PHP Syntax Error in ' . $filePath,
                'severity' => 'high',
                'description' => $error['message'],
                'remediation' => 'Fix the syntax error in the specified file.',
            ]);
        }
        
        // If the process failed for a reason other than finding lint errors (e.g., command not found).
        if (!$process->isSuccessful() && $errors === []) {
            $this->addFinding([
                'package' => 'Application Code',
                'title' => 'PHP Syntax Audit Failed to Run',
                'severity' => 'error',
                'description' => 'The PHP syntax audit process failed without reporting specific syntax errors.',
                'remediation' => 'Ensure `find`, `xargs`, and `php` are available. Error: ' . $process->getErrorOutput(),
            ]);
        }

        // The audit passes if no findings were added.
        return $this->findings === [];
    }

    protected function getProcess(): Process
    {
        $excludedDirsConfig = config('warden.audits.php_syntax.exclude', [
            'vendor',
            'node_modules',
            'storage',
            'bootstrap/cache',
            '.git',
        ]);

        /** @var array<int, string> $excludedDirs */
        $excludedDirs = is_array($excludedDirsConfig) ? array_values(array_filter($excludedDirsConfig, 'is_string')) : [];

        $pathsToPrune = collect($excludedDirs)
            ->map(fn (string $dir) => sprintf("-path './%s' -prune", $dir))
            ->implode(' -o ');

        $command = sprintf("find . %s -o -name '*.php' -print0 | xargs -0 -n1 -I{} php -l {}", $pathsToPrune);

        // fromShellCommandline is used to properly handle shell piping.
        return Process::fromShellCommandline($command, base_path());
    }

    /**
     * @return array<int, array{file: string, message: string}>
     */
    protected function parseOutput(string $output): array
    {
        $errors = [];
        $lines = explode("\n", trim($output));
        $counter = count($lines);

        for ($i = 0; $i < $counter; $i++) {
            if (str_contains($lines[$i], 'Errors parsing')) {
                // The filename is on the same line as "Errors parsing".
                $file = trim(substr($lines[$i], (int) strpos($lines[$i], 'parsing') + 7));
                $errorMessage = 'Syntax error detected.';

                // The detailed parse error message is usually on the next line.
                if (isset($lines[$i + 1]) && str_contains($lines[$i + 1], 'Parse error:')) {
                    $errorMessage = trim($lines[$i + 1]);
                }

                $errors[] = [
                    'file' => $file,
                    'message' => $errorMessage,
                ];
            }
        }

        return $errors;
    }
} 