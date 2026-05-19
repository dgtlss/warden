<?php

namespace Dgtlss\Warden\Data;

class ResolutionPlan
{
    /**
     * @param array<int, ResolutionPlanItem> $items
     * @param array<string, mixed> $filters
     */
    public function __construct(
        public readonly array $items,
        public readonly array $filters = [],
    ) {
    }

    /**
     * @return array<int, ResolutionPlanItem>
     */
    public function actionableItems(): array
    {
        return array_values(array_filter(
            $this->items,
            static fn (ResolutionPlanItem $item): bool => $item->actionable
        ));
    }

    /**
     * @return array<int, ResolutionPlanItem>
     */
    public function manualItems(): array
    {
        return array_values(array_filter(
            $this->items,
            static fn (ResolutionPlanItem $item): bool => !$item->actionable
        ));
    }

    public function hasResolvableItems(): bool
    {
        return $this->actionableItems() !== [];
    }

    /**
     * @return array<int, ResolutionPlanItem>
     */
    public function applicableItems(bool $allowMajor): array
    {
        return array_values(array_filter(
            $this->items,
            static fn (ResolutionPlanItem $item): bool => $item->canApply($allowMajor)
        ));
    }

    /**
     * @return array<int, string>
     */
    public function sources(): array
    {
        return array_values(array_unique(array_map(
            static fn (ResolutionPlanItem $item): string => $item->source,
            $this->items
        )));
    }
}
