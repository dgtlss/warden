<?php

namespace Dgtlss\Warden\Services;

use Carbon\CarbonImmutable;

class BaselineService
{
    public function isEnabled(): bool
    {
        return (bool) config('warden.baseline.enabled', true);
    }

    public function getPath(?string $path = null): string
    {
        $configured = $path ?? config('warden.baseline.path', base_path('.warden-baseline.json'));

        if (str_starts_with($configured, '/')) {
            return $configured;
        }

        return base_path($configured);
    }

    /**
     * @return array<string, mixed>
     */
    public function load(?string $path = null): array
    {
        $resolvedPath = $this->getPath($path);

        if (!file_exists($resolvedPath)) {
            return [
                'version' => 1,
                'generated_at' => null,
                'entries' => [],
            ];
        }

        $contents = file_get_contents($resolvedPath);
        if ($contents === false) {
            return [
                'version' => 1,
                'generated_at' => null,
                'entries' => [],
            ];
        }

        $decoded = json_decode($contents, true);

        if (!is_array($decoded)) {
            return [
                'version' => 1,
                'generated_at' => null,
                'entries' => [],
            ];
        }

        if (!isset($decoded['entries']) || !is_array($decoded['entries'])) {
            $decoded['entries'] = [];
        }

        return $decoded;
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     */
    public function write(array $findings, ?string $path = null, ?string $reason = null, ?string $expiresAt = null): string
    {
        $entries = array_map(function (array $finding) use ($reason, $expiresAt): array {
            return [
                'fingerprint' => $finding['fingerprint'] ?? null,
                'rule_id' => $finding['rule_id'] ?? null,
                'package' => $finding['package'] ?? null,
                'title' => $finding['title'] ?? null,
                'source' => $finding['source'] ?? null,
                'file' => $finding['file'] ?? null,
                'reason' => $reason ?? 'Accepted as existing baseline finding.',
                'expires_at' => $expiresAt,
            ];
        }, $findings);

        $payload = [
            'version' => 1,
            'generated_at' => CarbonImmutable::now()->toIso8601String(),
            'entries' => $entries,
        ];

        $resolvedPath = $this->getPath($path);

        file_put_contents(
            $resolvedPath,
            json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL
        );

        return $resolvedPath;
    }
}
