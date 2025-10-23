<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;

class PhpSyntaxAuditService extends AbstractAuditService
{
    public function getName(): string
    {
        return 'PHP Syntax';
    }

    /**
     * Get the default configuration for this audit.
     *
     * @return array
     */
    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'exclude' => env('WARDEN_PHP_SYNTAX_EXCLUDE') ? explode(',', env('WARDEN_PHP_SYNTAX_EXCLUDE')) : [
                'vendor',
                'node_modules',
                'storage',
                'bootstrap/cache',
                '.git',
            ],
            'timeout' => env('WARDEN_PHP_SYNTAX_TIMEOUT', 300),
            'max_files' => env('WARDEN_PHP_SYNTAX_MAX_FILES', 1000), // Limit files to check for performance
        ]);
    }

    public function run(): bool
    {
        $process = $this->getProcess();
        $process->setTimeout($this->getTimeout());
        $process->run();

        // The command's output can be on stdout or stderr, so we combine them.
        $output = $process->getOutput() . $process->getErrorOutput();
        $errors = $this->parseOutput($output);

        if (!empty($errors)) {
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
        }
        
        // If the process failed for a reason other than finding lint errors (e.g., command not found).
        if (!$process->isSuccessful() && empty($errors)) {
            $this->addFinding([
                'package' => 'Application Code',
                'title' => 'PHP Syntax Audit Failed to Run',
                'severity' => 'error',
                'description' => 'The PHP syntax audit process failed without reporting specific syntax errors.',
                'remediation' => 'Ensure `find`, `xargs`, and `php` are available. Error: ' . $process->getErrorOutput(),
            ]);
        }

        // The audit passes if no findings were added.
        return empty($this->findings);
    }

    protected function getProcess(): Process
    {
        $excludedDirs = $this->getConfigValue('exclude', [
            'vendor',
            'node_modules',
            'storage',
            'bootstrap/cache',
            '.git',
        ]);

        $pathsToPrune = collect($excludedDirs)
            ->map(fn ($dir) => "-path './{$dir}' -prune")
            ->implode(' -o ');

        $command = "find . {$pathsToPrune} -o -name '*.php' -print0 | xargs -0 -n1 -I{} php -l {}";

        // fromShellCommandline is used to properly handle shell piping.
        return Process::fromShellCommandline($command, base_path());
    }

    protected function parseOutput(string $output): array
    {
        $errors = [];
        $lines = explode("\n", trim($output));

        for ($i = 0; $i < count($lines); $i++) {
            if (str_contains($lines[$i], 'Errors parsing')) {
                // The filename is on the same line as "Errors parsing".
                $file = trim(substr($lines[$i], strpos($lines[$i], 'parsing') + 7));
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