<?php

namespace Dgtlss\Warden\Services;

use Carbon\CarbonImmutable;

class PolicyService
{
    public function __construct(protected BaselineService $baselineService)
    {
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     * @return array{active: array<int, array<string, mixed>>, suppressed: array<int, array<string, mixed>>}
     */
    public function applySuppressions(array $findings): array
    {
        $entries = $this->suppressionEntries();
        $active = [];
        $suppressed = [];

        foreach ($findings as $finding) {
            $matchedEntry = $this->matchingEntry($finding, $entries);

            if ($matchedEntry === null) {
                $active[] = $finding;
                continue;
            }

            $finding['suppression'] = [
                'reason' => $matchedEntry['reason'] ?? 'Suppressed by policy.',
                'expires_at' => $matchedEntry['expires_at'] ?? null,
            ];

            $suppressed[] = $finding;
        }

        return [
            'active' => $active,
            'suppressed' => $suppressed,
        ];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function suppressionEntries(): array
    {
        $entries = [];
        $configured = config('warden.policy.suppressions', []);

        if (is_array($configured)) {
            foreach ($configured as $entry) {
                if (is_array($entry) && !$this->isExpired($entry)) {
                    $entries[] = $entry;
                }
            }
        }

        if ($this->baselineService->isEnabled()) {
            $baseline = $this->baselineService->load();
            foreach ($baseline['entries'] as $entry) {
                if (is_array($entry) && !$this->isExpired($entry)) {
                    $entries[] = $entry;
                }
            }
        }

        return $entries;
    }

    /**
     * @param array<int, array<string, mixed>> $entries
     * @return array<string, mixed>|null
     */
    protected function matchingEntry(array $finding, array $entries): ?array
    {
        foreach ($entries as $entry) {
            if (isset($entry['fingerprint'])) {
                if (($finding['fingerprint'] ?? null) === $entry['fingerprint']) {
                    return $entry;
                }

                continue;
            }

            if (isset($entry['rule_id']) && ($finding['rule_id'] ?? null) !== $entry['rule_id']) {
                continue;
            }

            if (isset($entry['package']) && ($finding['package'] ?? null) !== $entry['package']) {
                continue;
            }

            if (isset($entry['file']) && ($finding['file'] ?? null) !== $entry['file']) {
                continue;
            }

            return $entry;
        }

        return null;
    }

    /**
     * @param array<string, mixed> $entry
     */
    protected function isExpired(array $entry): bool
    {
        if (!isset($entry['expires_at']) || !is_string($entry['expires_at']) || $entry['expires_at'] === '') {
            return false;
        }

        return CarbonImmutable::parse($entry['expires_at'])->isPast();
    }
}
