<?php

namespace Dgtlss\Warden\Tests\Services;

use Dgtlss\Warden\Data\AuditRunReport;
use Dgtlss\Warden\Data\CommandResult;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\ProcessRunner;
use Dgtlss\Warden\Services\Resolve\ComposerResolver;
use Dgtlss\Warden\Services\Resolve\JavascriptResolver;
use Dgtlss\Warden\Services\ResolverRegistry;
use Dgtlss\Warden\Services\ResolutionPlanner;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;

class ResolutionPlannerTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    public function testDirectComposerFindingProducesTargetedUpdatePlan(): void
    {
        $runner = \Mockery::mock(ProcessRunner::class);
        $runner->shouldReceive('run')->never();
        $runner->shouldReceive('commandExists')->never();

        $planner = $this->makePlanner($runner);
        $report = $this->reportWithFindings([[
            'source' => 'composer',
            'package' => 'laravel/framework',
            'title' => 'Upgrade laravel/framework',
            'rule_id' => 'CVE-2026-0001',
            'category' => 'dependency',
            'severity' => 'high',
            'description' => 'Upgrade laravel/framework',
            'resolvable' => true,
            'resolver_type' => 'composer',
            'is_direct_dependency' => true,
            'is_dev_dependency' => false,
            'declared_constraint' => '^12.0',
            'installed_version' => '12.0.0',
        ]]);

        $plan = $planner->buildPlan($report);

        $this->assertCount(1, $plan->items);
        $this->assertSame('composer', $plan->items[0]->source);
        $this->assertSame('composer update laravel/framework --with-all-dependencies --no-interaction', $plan->items[0]->displayCommands()[0]);
    }

    public function testDuplicateComposerFindingsCollapseIntoOneOperation(): void
    {
        $runner = \Mockery::mock(ProcessRunner::class);
        $runner->shouldReceive('run')->never();
        $runner->shouldReceive('commandExists')->never();

        $planner = $this->makePlanner($runner);
        $report = $this->reportWithFindings([
            [
                'source' => 'composer',
                'package' => 'laravel/framework',
                'title' => 'Upgrade laravel/framework',
                'rule_id' => 'CVE-2026-0001',
                'category' => 'dependency',
                'severity' => 'high',
                'description' => 'Upgrade laravel/framework',
                'resolvable' => true,
                'resolver_type' => 'composer',
                'is_direct_dependency' => true,
                'is_dev_dependency' => false,
                'declared_constraint' => '^12.0',
                'installed_version' => '12.0.0',
            ],
            [
                'source' => 'composer',
                'package' => 'laravel/framework',
                'title' => 'Upgrade laravel/framework',
                'rule_id' => 'CVE-2026-9999',
                'category' => 'dependency',
                'severity' => 'high',
                'description' => 'Upgrade laravel/framework',
                'resolvable' => true,
                'resolver_type' => 'composer',
                'is_direct_dependency' => true,
                'is_dev_dependency' => false,
                'declared_constraint' => '^12.0',
                'installed_version' => '12.0.0',
            ],
        ]);

        $plan = $planner->buildPlan($report);

        $this->assertCount(1, $plan->items);
        $this->assertCount(2, $plan->items[0]->ruleIds);
    }

    public function testAbandonedDirectPackageProducesReplacementPlan(): void
    {
        $runner = \Mockery::mock(ProcessRunner::class);
        $runner->shouldReceive('run')->never();
        $runner->shouldReceive('commandExists')->never();

        $planner = $this->makePlanner($runner);
        $report = new AuditRunReport(
            results: [],
            findings: [],
            suppressedFindings: [],
            abandonedPackages: [[
                'package' => 'old/package',
                'replacement' => 'new/package',
                'is_direct_dependency' => true,
                'is_dev_dependency' => false,
                'declared_constraint' => '^1.0',
                'installed_version' => '1.2.0',
                'resolvable' => true,
            ]],
            hasFailures: false,
            durationMs: 0.0,
            profile: 'legacy',
            metadata: []
        );

        $plan = $planner->buildPlan($report);

        $this->assertCount(1, $plan->items);
        $this->assertSame('abandoned-replace', $plan->items[0]->strategy);
        $this->assertCount(2, $plan->items[0]->commands);
    }

    public function testTransitiveComposerFindingWithoutDeterministicParentIsManual(): void
    {
        $runner = \Mockery::mock(ProcessRunner::class);
        $runner->shouldReceive('run')->once()->andReturn(new CommandResult(
            ['composer', 'why', 'symfony/http-foundation', '--no-interaction', '--no-ansi'],
            1,
            '',
            'not found'
        ));
        $runner->shouldReceive('commandExists')->never();

        $planner = $this->makePlanner($runner);
        $report = $this->reportWithFindings([[
            'source' => 'composer',
            'package' => 'symfony/http-foundation',
            'title' => 'Upgrade symfony/http-foundation',
            'rule_id' => 'CVE-2026-0002',
            'category' => 'dependency',
            'severity' => 'high',
            'description' => 'Upgrade symfony/http-foundation',
            'resolvable' => true,
            'resolver_type' => 'composer',
            'is_direct_dependency' => false,
            'is_dev_dependency' => false,
        ]]);

        $plan = $planner->buildPlan($report);

        $this->assertCount(1, $plan->items);
        $this->assertFalse($plan->items[0]->actionable);
    }

    public function testJavascriptFindingMapsToPackageManagerCommand(): void
    {
        $runner = \Mockery::mock(ProcessRunner::class);
        $runner->shouldReceive('commandExists')->once()->with('pnpm')->andReturn(true);
        $runner->shouldReceive('run')->never();

        $planner = $this->makePlanner($runner);
        $report = $this->reportWithFindings([[
            'source' => 'npm',
            'package' => 'vite',
            'title' => 'Upgrade vite',
            'rule_id' => 'JS-2026-0001',
            'category' => 'dependency',
            'severity' => 'high',
            'description' => 'Upgrade vite',
            'resolvable' => true,
            'resolver_type' => 'javascript',
            'package_manager' => 'pnpm',
            'lockfile' => 'pnpm-lock.yaml',
            'is_direct_dependency' => true,
            'is_dev_dependency' => false,
            'declared_constraint' => '^5.0.0',
        ]]);

        $plan = $planner->buildPlan($report);

        $this->assertCount(1, $plan->items);
        $this->assertSame('pnpm up vite', $plan->items[0]->displayCommands()[0]);
    }

    protected function makePlanner(ProcessRunner $runner): ResolutionPlanner
    {
        return new ResolutionPlanner(new ResolverRegistry(
            new ComposerResolver($runner),
            new JavascriptResolver($runner),
        ));
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     */
    protected function reportWithFindings(array $findings): AuditRunReport
    {
        return new AuditRunReport(
            results: [],
            findings: $findings,
            suppressedFindings: [],
            abandonedPackages: [],
            hasFailures: false,
            durationMs: 0.0,
            profile: 'legacy',
            metadata: []
        );
    }
}
