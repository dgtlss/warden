<?php

namespace Dgtlss\Warden\Services\Audits\Concerns;

trait ScansTextFiles
{
    /**
     * @param array<int, string> $patterns
     * @return array<int, string>
     */
    protected function matchingFiles(array $patterns): array
    {
        $files = [];

        foreach ($patterns as $pattern) {
            foreach (glob(base_path($pattern)) ?: [] as $match) {
                if (is_file($match)) {
                    $files[] = $match;
                }
            }
        }

        return array_values(array_unique($files));
    }

    /**
     * @return array{content: string, relative: string}|null
     */
    protected function readFile(string $path): ?array
    {
        $content = file_get_contents($path);

        if ($content === false) {
            return null;
        }

        return [
            'content' => $content,
            'relative' => ltrim(str_replace(base_path(), '', $path), DIRECTORY_SEPARATOR),
        ];
    }

    protected function lineNumberForSnippet(string $content, string $snippet): ?int
    {
        $lines = preg_split('/\R/', $content) ?: [];

        foreach ($lines as $index => $line) {
            if (str_contains($line, $snippet)) {
                return $index + 1;
            }
        }

        return null;
    }
}
