<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Source;

use Dgtlss\Warden\ValueObjects\AuditError;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\SplFileInfo;

final class SourceFileDiscovery
{
    /** @var list<AuditError> */
    private array $discoveryErrors = [];

    /** @return array{php: list<SplFileInfo>, blade: list<SplFileInfo>, secrets: list<SplFileInfo>, errors: list<AuditError>, skipped: int} */
    public function discover(): array
    {
        $this->discoveryErrors = [];
        $maxKb = config('warden.audits.source.max_file_size_kb', 1024);
        $exclude = config('warden.audits.source.exclude', []);
        $phpPaths = config('warden.audits.source.php_paths', []);
        $bladePaths = config('warden.audits.source.blade_paths', []);

        if (!is_int($maxKb) || $maxKb < 1 || $maxKb > 10240 || !is_array($exclude) || !is_array($phpPaths) || !is_array($bladePaths)) {
            return ['skipped' => 0, 'php' => [], 'blade' => [], 'secrets' => [], 'errors' => [new AuditError('source', 'invalid_configuration', 'Source paths, exclusions, and max_file_size_kb must be valid.')]];
        }

        if (!$this->validPaths($exclude) || !$this->validPaths($phpPaths) || !$this->validPaths($bladePaths)) {
            return ['skipped' => 0, 'php' => [], 'blade' => [], 'secrets' => [], 'errors' => [new AuditError('source', 'invalid_configuration', 'Source paths must be non-empty paths relative to the application root.')]];
        }

        $excludedPaths = $this->stringList($exclude);
        $secrets = $this->filesWithin(['*.php', '*.blade.php', '*.js', '*.ts', '*.json', '*.yaml', '*.yml', '.env.example'], $excludedPaths);
        $php = array_values(array_filter($secrets, fn (SplFileInfo $file): bool => str_ends_with($file->getFilename(), '.php') && $this->withinPaths($file, $this->stringList($phpPaths))));
        $blade = array_values(array_filter($secrets, fn (SplFileInfo $file): bool => str_ends_with($file->getFilename(), '.blade.php') && $this->withinPaths($file, $this->stringList($bladePaths))));

        $errors = $this->discoveryErrors;
        $skipped = [];
        $limit = $maxKb * 1024;
        foreach (array_merge($php, $blade, $secrets) as $file) {
            if (!$file->isReadable()) {
                $errors[$file->getPathname()] = new AuditError('source', 'unreadable_file', sprintf('Unable to read %s.', $file->getRelativePathname()));
            } elseif ($file->getSize() > $limit) {
                $errors[$file->getPathname()] = new AuditError('source', 'file_too_large', sprintf('%s exceeds the configured source file limit.', $file->getRelativePathname()));
            }
        }

        foreach ($errors as $error) {
            if (in_array($error->code, ['unreadable_file', 'file_too_large'], true)) {
                $skipped[$error->message] = true;
            }
        }

        $allowed = static fn (SplFileInfo $file): bool => $file->isReadable() && $file->getSize() <= $limit && $file->getFilename() !== '.env';

        return [
            'php' => array_values(array_filter($php, $allowed)),
            'blade' => array_values(array_filter($blade, $allowed)),
            'secrets' => array_values(array_filter($secrets, $allowed)),
            'errors' => array_values($errors),
            'skipped' => count($skipped),
        ];
    }

    /**
     * @param list<string> $names
     * @param list<string> $exclude
     * @return list<SplFileInfo>
     */
    private function filesWithin(array $names, array $exclude): array
    {
        $finder = Finder::create()->files()->ignoreDotFiles(false)->ignoreVCS(true)->in(base_path());
        foreach ($names as $name) {
            $finder->name($name);
        }

        foreach ($exclude as $path) {
            $finder->notPath($path)->exclude($path);
        }

        $files = [];
        try {
            foreach ($this->iterate($finder) as $file) {
                $files[] = $file;
            }
        } catch (\Symfony\Component\Finder\Exception\AccessDeniedException $accessDeniedException) {
            $this->discoveryErrors[] = new AuditError('source', 'unreadable_directory', $accessDeniedException->getMessage());
        }

        usort($files, static fn (SplFileInfo $a, SplFileInfo $b): int => $a->getRealPath() <=> $b->getRealPath());

        return $files;
    }

    /** @param list<string> $paths */
    private function withinPaths(SplFileInfo $file, array $paths): bool
    {
        foreach ($paths as $path) {
            // Finder returns paths relative to the root, without dot segments.
            $segments = array_filter(explode('/', str_replace(DIRECTORY_SEPARATOR, '/', $path)), static fn (string $segment): bool => $segment !== '' && $segment !== '.');
            $path = implode('/', $segments);
            $relativePath = str_replace(DIRECTORY_SEPARATOR, '/', $file->getRelativePathname());
            if ($path === '' || str_starts_with($relativePath, $path . '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return iterable<SplFileInfo>
     * @throws \Symfony\Component\Finder\Exception\AccessDeniedException
     */
    private function iterate(Finder $finder): iterable
    {
        yield from $finder;
    }

    /**
     * @param array<mixed> $items
     * @return list<string>
     */
    private function stringList(array $items): array
    {
        return array_values(array_filter($items, static fn (mixed $item): bool => is_string($item) && trim($item) !== ''));
    }

    /** @param array<mixed> $paths */
    private function validPaths(array $paths): bool
    {
        foreach ($paths as $path) {
            if (!is_string($path) || trim($path) === '' || str_starts_with($path, DIRECTORY_SEPARATOR) || preg_match('#(^|[\\/])\.\.([\\/]|$)#', $path) === 1) {
                return false;
            }
        }

        return true;
    }
}
