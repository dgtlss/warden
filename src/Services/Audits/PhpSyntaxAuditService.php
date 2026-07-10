<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Symfony\Component\Process\Process;

class PhpSyntaxAuditService implements AuditServiceInterface
{
    public function getName(): string
    {
        return 'php-syntax';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        $findings = [];
        foreach ($this->phpFiles() as $path) {
            $process = new Process([PHP_BINARY, '-l', $path], base_path(), null, null, $auditContext->timeout);
            $process->run();
            if ($process->isSuccessful()) {
                continue;
            }

            $relativePath = ltrim(str_replace(base_path(), '', $path), DIRECTORY_SEPARATOR);
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
        foreach ($excluded as $directory) {
            if ($path === $directory || str_starts_with($path, rtrim($directory, '/') . DIRECTORY_SEPARATOR)) {
                return true;
            }
        }

        return false;
    }
}
