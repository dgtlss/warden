<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Data\ResolutionPlanItem;
use Dgtlss\Warden\Services\Resolve\ComposerResolver;
use Dgtlss\Warden\Services\Resolve\FindingResolverInterface;
use Dgtlss\Warden\Services\Resolve\JavascriptResolver;

class ResolverRegistry
{
    /**
     * @var array<string, FindingResolverInterface>
     */
    protected array $ruleResolvers;

    /**
     * @var array<string, FindingResolverInterface>
     */
    protected array $categoryResolvers;

    public function __construct(
        protected ComposerResolver $composerResolver,
        protected JavascriptResolver $javascriptResolver,
    ) {
        $this->ruleResolvers = [
            'composer.abandoned' => $this->composerResolver,
        ];

        $this->categoryResolvers = [
            'dependency' => $this->composerResolver,
        ];
    }

    /**
     * @param array<string, mixed> $finding
     * @param array<string, mixed> $options
     */
    public function planForFinding(array $finding, array $options = []): ?ResolutionPlanItem
    {
        $resolver = $this->resolverForFinding($finding, $options);

        return $resolver?->plan($finding, $options);
    }

    /**
     * @param array<string, mixed> $finding
     * @param array<string, mixed> $options
     */
    protected function resolverForFinding(array $finding, array $options = []): ?FindingResolverInterface
    {
        $ruleId = isset($finding['rule_id']) && is_string($finding['rule_id']) ? $finding['rule_id'] : null;
        if ($ruleId !== null) {
            foreach ($this->ruleResolvers as $prefix => $resolver) {
                if (str_starts_with($ruleId, $prefix) && $resolver->supports($finding, $options)) {
                    return $resolver;
                }
            }
        }

        $category = isset($finding['category']) && is_string($finding['category']) ? $finding['category'] : null;
        $source = isset($finding['source']) && is_string($finding['source']) ? $finding['source'] : null;

        if (($finding['resolver_type'] ?? null) === 'composer' || $source === 'composer') {
            return $this->composerResolver->supports($finding, $options) ? $this->composerResolver : null;
        }

        if (($finding['resolver_type'] ?? null) === 'javascript' || $source === 'npm') {
            return $this->javascriptResolver->supports($finding, $options) ? $this->javascriptResolver : null;
        }

        if ($category !== null && isset($this->categoryResolvers[$category])) {
            $resolver = $this->categoryResolvers[$category];

            return $resolver->supports($finding, $options) ? $resolver : null;
        }

        return null;
    }
}
