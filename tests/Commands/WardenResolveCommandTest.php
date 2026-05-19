<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Data\AuditRunReport;
use Dgtlss\Warden\Data\ResolutionExecutionReport;
use Dgtlss\Warden\Data\ResolutionPlan;
use Dgtlss\Warden\Data\ResolutionPlanItem;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\AuditHistoryService;
use Dgtlss\Warden\Services\AuditManager;
use Dgtlss\Warden\Services\ProcessRunner;
use Dgtlss\Warden\Services\ResolutionExecutor;
use Dgtlss\Warden\Services\ResolutionPlanner;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;

class WardenResolveCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    protected function tearDown(): void
    {
        putenv('CI');

        parent::tearDown();
    }

    public function testResolveCommandShowsPreviewForPlan(): void
    {
        $plan = new ResolutionPlan([
            new ResolutionPlanItem(
                id: 'composer-update',
                source: 'composer',
                package: 'laravel/framework',
                title: 'Update Composer package laravel/framework',
                ruleIds: ['CVE-2026-0001'],
                commands: [[
                    'command' => ['composer', 'update', 'laravel/framework', '--with-all-dependencies', '--no-interaction'],
                    'display' => 'composer update laravel/framework --with-all-dependencies --no-interaction',
                ]],
                expectedFiles: ['composer.lock'],
                riskLevel: 'safe',
                requiresNetwork: true,
                verificationSteps: ['composer phpstan', 'vendor/bin/phpunit tests/', 'warden:audit --no-notify'],
                strategy: 'update-package',
            ),
        ]);

        $this->mock(AuditManager::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->once()->andReturn(new AuditRunReport(
                results: [],
                findings: [],
                suppressedFindings: [],
                abandonedPackages: [],
                hasFailures: false,
                durationMs: 0.0,
                profile: 'legacy',
                metadata: []
            ));
        });

        $this->mock(ResolutionPlanner::class, function (MockInterface $mock) use ($plan): void {
            $mock->shouldReceive('buildPlan')->once()->andReturn($plan);
        });

        $this->mock(AuditHistoryService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('appendResolutionAttemptToLatest')->once();
        });

        $this->artisan('warden:resolve')
            ->expectsOutputToContain('Update Composer package laravel/framework')
            ->expectsOutputToContain('composer update laravel/framework --with-all-dependencies --no-interaction')
            ->assertExitCode(0);
    }

    public function testResolveCommandHandlesNoResolvableItems(): void
    {
        $this->mock(AuditManager::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->once()->andReturn(new AuditRunReport(
                results: [],
                findings: [],
                suppressedFindings: [],
                abandonedPackages: [],
                hasFailures: false,
                durationMs: 0.0,
                profile: 'legacy',
                metadata: []
            ));
        });

        $this->mock(ResolutionPlanner::class, function (MockInterface $mock): void {
            $mock->shouldReceive('buildPlan')->once()->andReturn(new ResolutionPlan([]));
        });

        $this->mock(AuditHistoryService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('appendResolutionAttemptToLatest')->once();
        });

        $this->artisan('warden:resolve')
            ->expectsOutputToContain('No auto-resolvable dependency findings were available for the selected filters.')
            ->assertExitCode(0);
    }

    public function testResolveCommandRefusesToRunInCiByDefault(): void
    {
        putenv('CI=true');

        $this->artisan('warden:resolve')
            ->expectsOutputToContain('warden:resolve is disabled in CI by default')
            ->assertExitCode(1);
    }

    public function testResolveCommandRefusesDirtyApplyWithoutAllowDirty(): void
    {
        $plan = new ResolutionPlan([
            new ResolutionPlanItem(
                id: 'composer-update',
                source: 'composer',
                package: 'laravel/framework',
                title: 'Update Composer package laravel/framework',
                ruleIds: ['CVE-2026-0001'],
                commands: [[
                    'command' => ['composer', 'update', 'laravel/framework', '--with-all-dependencies', '--no-interaction'],
                    'display' => 'composer update laravel/framework --with-all-dependencies --no-interaction',
                ]],
                expectedFiles: ['composer.lock'],
                riskLevel: 'safe',
                requiresNetwork: true,
                verificationSteps: ['composer phpstan'],
                strategy: 'update-package',
            ),
        ]);

        $this->mock(AuditManager::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->once()->andReturn(new AuditRunReport(
                results: [],
                findings: [],
                suppressedFindings: [],
                abandonedPackages: [],
                hasFailures: false,
                durationMs: 0.0,
                profile: 'legacy',
                metadata: []
            ));
        });

        $this->mock(ResolutionPlanner::class, function (MockInterface $mock) use ($plan): void {
            $mock->shouldReceive('buildPlan')->once()->andReturn($plan);
        });

        $this->mock(AuditHistoryService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('appendResolutionAttemptToLatest')->once();
        });

        $this->mock(ProcessRunner::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->twice()->andReturn(
                new \Dgtlss\Warden\Data\CommandResult(['git', 'rev-parse', '--is-inside-work-tree'], 0, "true\n", ''),
                new \Dgtlss\Warden\Data\CommandResult(['git', 'status', '--short'], 0, " M composer.lock\n", '')
            );
        });

        $this->artisan('warden:resolve', ['--apply' => true])
            ->expectsOutputToContain('The working tree has uncommitted changes.')
            ->assertExitCode(1);
    }

    public function testResolveCommandPassesFiltersToPlanner(): void
    {
        $this->mock(AuditManager::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->once()->andReturn(new AuditRunReport(
                results: [],
                findings: [],
                suppressedFindings: [],
                abandonedPackages: [],
                hasFailures: false,
                durationMs: 0.0,
                profile: 'legacy',
                metadata: []
            ));
        });

        $this->mock(ResolutionPlanner::class, function (MockInterface $mock): void {
            $mock->shouldReceive('buildPlan')
                ->once()
                ->with(
                    \Mockery::type(AuditRunReport::class),
                    \Mockery::on(static fn (array $options): bool => $options['source'] === 'composer'
                        && $options['package'] === 'laravel/framework'
                        && $options['rule'] === 'CVE-2026-0001')
                )
                ->andReturn(new ResolutionPlan([]));
        });

        $this->mock(AuditHistoryService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('appendResolutionAttemptToLatest')->once();
        });

        $this->artisan('warden:resolve', [
            '--source' => 'composer',
            '--package' => 'laravel/framework',
            '--rule' => 'CVE-2026-0001',
        ])->assertExitCode(0);
    }

    public function testResolveCommandAppliesPlanThroughExecutor(): void
    {
        $plan = new ResolutionPlan([
            new ResolutionPlanItem(
                id: 'composer-update',
                source: 'composer',
                package: 'laravel/framework',
                title: 'Update Composer package laravel/framework',
                ruleIds: ['CVE-2026-0001'],
                commands: [[
                    'command' => ['composer', 'update', 'laravel/framework', '--with-all-dependencies', '--no-interaction'],
                    'display' => 'composer update laravel/framework --with-all-dependencies --no-interaction',
                ]],
                expectedFiles: ['composer.lock'],
                riskLevel: 'safe',
                requiresNetwork: true,
                verificationSteps: ['composer phpstan'],
                strategy: 'update-package',
            ),
        ]);

        $this->mock(AuditManager::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->once()->andReturn(new AuditRunReport(
                results: [],
                findings: [],
                suppressedFindings: [],
                abandonedPackages: [],
                hasFailures: false,
                durationMs: 0.0,
                profile: 'legacy',
                metadata: []
            ));
        });

        $this->mock(ResolutionPlanner::class, function (MockInterface $mock) use ($plan): void {
            $mock->shouldReceive('buildPlan')->once()->andReturn($plan);
        });

        $this->mock(AuditHistoryService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('appendResolutionAttemptToLatest')->once();
        });

        $this->mock(ProcessRunner::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->twice()->andReturn(
                new \Dgtlss\Warden\Data\CommandResult(['git', 'rev-parse', '--is-inside-work-tree'], 0, "true\n", ''),
                new \Dgtlss\Warden\Data\CommandResult(['git', 'status', '--short'], 0, '', '')
            );
        });

        $this->mock(ResolutionExecutor::class, function (MockInterface $mock): void {
            $mock->shouldReceive('execute')->once()->andReturn(new ResolutionExecutionReport(
                success: true,
                applied: [[
                    'item' => ['package' => 'laravel/framework'],
                    'status' => 'applied',
                ]],
                skipped: [],
                verification: [],
                postAuditReport: new AuditRunReport(
                    results: [],
                    findings: [],
                    suppressedFindings: [],
                    abandonedPackages: [],
                    hasFailures: false,
                    durationMs: 0.0,
                    profile: 'legacy',
                    metadata: []
                )
            ));
        });

        $this->artisan('warden:resolve', ['--apply' => true])
            ->expectsOutputToContain('Resolution Summary')
            ->assertExitCode(0);
    }
}
