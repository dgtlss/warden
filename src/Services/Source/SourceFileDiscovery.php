<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Source;

use Dgtlss\Warden\ValueObjects\AuditError;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\SplFileInfo;

final class SourceFileDiscovery
{
    /** @return array{php: list<SplFileInfo>, blade: list<SplFileInfo>, secrets: list<SplFileInfo>, errors: list<AuditError>} */
    public function discover(): array
    {
        $maxKb = config('warden.audits.source.max_file_size_kb', 1024);
        $exclude = config('warden.audits.source.exclude', []);
        $phpPaths = config('warden.audits.source.php_paths', []);
        $bladePaths = config('warden.audits.source.blade_paths', []);

        if (!is_int($maxKb) || $maxKb < 1 || $maxKb > 10240 || !is_array($exclude) || !is_array($phpPaths) || !is_array($bladePaths)) {
            return ['php' => [], 'blade' => [], 'secrets' => [], 'errors' => [new AuditError('source', 'invalid_configuration', 'Source paths, exclusions, and max_file_size_kb must be valid.')]];
        }

        if (!$this->validPaths($exclude) || !$this->validPaths($phpPaths) || !$this->validPaths($bladePaths)) {
            return ['php' => [], 'blade' => [], 'secrets' => [], 'errors' => [new AuditError('source', 'invalid_configuration', 'Source paths must be non-empty paths relative to the application root.')]];
        }

        $excludedPaths = $this->stringList($exclude);
        $php = $this->filesWithin($this->stringList($phpPaths), ['*.php'], $excludedPaths);
        $blade = $this->filesWithin($this->stringList($bladePaths), ['*.blade.php'], $excludedPaths);
        $secrets = $this->filesWithin(['.'], ['*.php', '*.blade.php', '*.js', '*.ts', '*.json', '*.yaml', '*.yml', '.env.example'], $excludedPaths);

        $errors = [];
        $limit = $maxKb * 1024;
        foreach (array_merge($php, $blade, $secrets) as $file) {
            if (!$file->isReadable()) {
                $errors[$file->getRelativePathname()] = new AuditError('source', 'unreadable_file', sprintf('Unable to read %s.', $file->getRelativePathname()));
            } elseif ($file->getSize() > $limit) {
                $errors[$file->getRelativePathname()] = new AuditError('source', 'file_too_large', sprintf('%s exceeds the configured source file limit.', $file->getRelativePathname()));
            }
        }

        $allowed = static fn (SplFileInfo $file): bool => $file->isReadable() && $file->getSize() <= $limit && $file->getFilename() !== '.env';

        return [
            'php' => array_values(array_filter($php, $allowed)),
            'blade' => array_values(array_filter($blade, $allowed)),
            'secrets' => array_values(array_filter($secrets, $allowed)),
            'errors' => array_values($errors),
        ];
    }

    /**
     * @param list<string> $paths
     * @param list<string> $names
     * @param list<string> $exclude
     * @return list<SplFileInfo>
     */
    private function filesWithin(array $paths, array $names, array $exclude): array
    {
        $existing = array_values(array_filter($paths, static fn (string $path): bool => is_dir(base_path($path))));
        if ($existing === []) {
            return [];
        }

        $finder = Finder::create()->files()->ignoreUnreadableDirs()->in(array_map(base_path(...), $existing));
        foreach ($names as $name) {
            $finder->name($name);
        }

        foreach ($exclude as $path) {
            $finder->notPath($path);
        }

        $files = iterator_to_array($finder, false);
        usort($files, static fn (SplFileInfo $a, SplFileInfo $b): int => $a->getRealPath() <=> $b->getRealPath());

        return $files;
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
