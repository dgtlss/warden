<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Data\Finding;

class FindingNormalizer
{
    /**
     * @param array<int, array<string, mixed>> $findings
     * @return array<int, Finding>
     */
    public function normalize(array $findings, string $source, string $auditId): array
    {
        $normalized = [];

        foreach ($findings as $finding) {
            $normalized[] = Finding::fromArray($finding, $source, $auditId);
        }

        return $normalized;
    }
}
