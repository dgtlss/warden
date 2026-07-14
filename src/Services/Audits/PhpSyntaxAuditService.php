<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

class PhpSyntaxAuditService implements AuditServiceInterface
{
    public function getName(): string
    {
        return 'php-syntax';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        $startedAt = microtime(true);
        $findings = [];
        foreach ($this->phpFiles() as $path) {
            $relativePath = $this->relativePath($path);
            $remaining = $auditContext->timeout - (microtime(true) - $startedAt);
            if ($remaining <= 0) {
                return new AuditResult($this->getName(), $findings, [new AuditError(
                    $this->getName(),
                    'timeout',
                    sprintf('PHP syntax analysis exceeded the configured timeout before linting %s.', $relativePath),
                )]);
            }

            $process = $this->createProcess($path, $remaining);
            try {
                $process->run();
            } catch (ProcessTimedOutException) {
                return new AuditResult($this->getName(), $findings, [new AuditError(
                    $this->getName(),
                    'timeout',
                    sprintf('PHP syntax analysis exceeded the configured timeout while linting %s.', $relativePath),
                )]);
            }

            if ($process->isSuccessful()) {
                continue;
            }

            $findings[] = new Finding(
                id: 'quality.php.syntax',
                source: $this->getName(),
                title: 'PHP syntax error',
                severity: Severity::High,
                description: trim($process->getErrorOutput() . "\n" . $process->getOutput()),
                remediation: 'Correct the parse error before deployment.',
                path: $relativePath,
            );
        }

        return AuditResult::complete($this->getName(), $findings);
    }

    protected function createProcess(string $path, float $timeout): Process
    {
        return new Process([PHP_BINARY, '-l', $path], base_path(), null, null, $timeout);
    }

    /** @return list<string> */
    private function phpFiles(): array
    {
        $excluded = config('warden.audits.php_syntax.exclude', [
            'vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git',
        ]);
        $excluded = is_array($excluded) ? array_values(array_filter($excluded, 'is_string')) : [];

        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(base_path(), RecursiveDirectoryIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $relativePath = ltrim(str_replace(base_path(), '', $file->getPathname()), DIRECTORY_SEPARATOR);
            if ($this->isExcluded($relativePath, $excluded)) {
                continue;
            }

            $files[] = $file->getPathname();
        }

        sort($files);

        return $files;
    }

    /** @param list<string> $excluded */
    private function isExcluded(string $path, array $excluded): bool
    {
        $normalisedPath = str_replace('\\', '/', $path);
        foreach ($excluded as $directory) {
            $normalisedDirectory = rtrim(str_replace('\\', '/', $directory), '/');
            if ($normalisedPath === $normalisedDirectory || str_starts_with($normalisedPath, $normalisedDirectory . '/')) {
                return true;
            }
        }

        return false;
    }

    private function relativePath(string $path): string
    {
        return ltrim(str_replace(base_path(), '', $path), DIRECTORY_SEPARATOR);
    }
}
