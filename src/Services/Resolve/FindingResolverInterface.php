<?php

namespace Dgtlss\Warden\Services\Resolve;

use Dgtlss\Warden\Data\ResolutionPlanItem;

interface FindingResolverInterface
{
    /**
     * @param array<string, mixed> $finding
     * @param array<string, mixed> $options
     */
    public function supports(array $finding, array $options = []): bool;

    /**
     * @param array<string, mixed> $finding
     * @param array<string, mixed> $options
     */
    public function plan(array $finding, array $options = []): ?ResolutionPlanItem;
}
