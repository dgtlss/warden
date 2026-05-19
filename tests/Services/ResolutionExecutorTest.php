<?php

namespace Dgtlss\Warden\Tests\Services;

use Dgtlss\Warden\Data\AuditRunReport;
use Dgtlss\Warden\Data\CommandResult;
use Dgtlss\Warden\Data\ResolutionPlan;
use Dgtlss\Warden\Data\ResolutionPlanItem;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\AuditHistoryService;
use Dgtlss\Warden\Services\AuditManager;
use Dgtlss\Warden\Services\ProcessRunner;
use Dgtlss\Warden\Services\ResolutionExecutor;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;

class ResolutionExecutorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    public function testSuccessfulApplyRunsVerificationAndPostAudit(): void
    {
        $runner = \Mockery::mock(ProcessRunner::class);
        $runner->shouldReceive('run')->times(2)->andReturn(
            new CommandResult(['composer', 'update', 'laravel/framework', '--with-all-dependencies', '--no-interaction'], 0, 'updated', ''),
            new CommandResult(['composer', 'phpstan'], 0, 'ok', ''),
        );

        $auditManager = \Mockery::mock(AuditManager::class);
        $auditManager->shouldReceive('run')->once()->andReturn(new AuditRunReport(
            results: [],
            findings: [],
            suppressedFindings: [],
            abandonedPackages: [],
            hasFailures: false,
            durationMs: 0.0,
            profile: 'legacy',
            metadata: []
        ));

        $history = \Mockery::mock(AuditHistoryService::class);
        $history->shouldReceive('appendResolutionAttemptToLatest')->once();

        $executor = new ResolutionExecutor($runner, $auditManager, $history);
        $report = $executor->execute($this->safePlan(), []);

        $this->assertTrue($report->success);
        $this->assertCount(1, $report->applied);
        $this->assertNotEmpty($report->verification);
        $this->assertNotNull($report->postAuditReport);
    }

    public function testFailedApplyStopsExecution(): void
    {
        $runner = \Mockery::mock(ProcessRunner::class);
        $runner->shouldReceive('run')->once()->andReturn(
            new CommandResult(['composer', 'update', 'laravel/framework', '--with-all-dependencies', '--no-interaction'], 1, '', 'failed')
        );

        $auditManager = \Mockery::mock(AuditManager::class);
        $auditManager->shouldReceive('run')->never();

        $history = \Mockery::mock(AuditHistoryService::class);
        $history->shouldReceive('appendResolutionAttemptToLatest')->once();

        $executor = new ResolutionExecutor($runner, $auditManager, $history);
        $report = $executor->execute($this->safePlan(), []);

        $this->assertFalse($report->success);
        $this->assertNotNull($report->failureMessage);
    }

    public function testHighRiskItemsAreSkippedWithoutAllowMajor(): void
    {
        $runner = \Mockery::mock(ProcessRunner::class);
        $runner->shouldReceive('run')->never();

        $auditManager = \Mockery::mock(AuditManager::class);
        $auditManager->shouldReceive('run')->never();

        $history = \Mockery::mock(AuditHistoryService::class);
        $history->shouldReceive('appendResolutionAttemptToLatest')->never();

        $executor = new ResolutionExecutor($runner, $auditManager, $history);
        $report = $executor->execute($this->highRiskPlan(), ['allow_major' => false]);

        $this->assertTrue($report->success);
        $this->assertCount(0, $report->applied);
        $this->assertCount(1, $report->skipped);
        $this->assertNull($report->postAuditReport);
    }

    protected function safePlan(): ResolutionPlan
    {
        return new ResolutionPlan([
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
                verificationSteps: ['composer phpstan', 'vendor/bin/phpunit tests/'],
                strategy: 'update-package',
            ),
        ]);
    }

    protected function highRiskPlan(): ResolutionPlan
    {
        return new ResolutionPlan([
            new ResolutionPlanItem(
                id: 'npm-major',
                source: 'npm',
                package: 'vite',
                title: 'Review major npm upgrade for vite',
                ruleIds: ['JS-2026-0001'],
                commands: [[
                    'command' => ['npm', 'install', 'vite@latest'],
                    'display' => 'npm install vite@latest',
                ]],
                expectedFiles: ['package.json', 'package-lock.json'],
                riskLevel: 'high-risk',
                requiresNetwork: true,
                verificationSteps: ['warden:audit --no-notify'],
                strategy: 'major-update',
            ),
        ]);
    }
}
