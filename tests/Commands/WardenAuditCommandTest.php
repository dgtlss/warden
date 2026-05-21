<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\AuditExecutor;
use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use Dgtlss\Warden\Services\Audits\EnvAuditService;
use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;

class WardenAuditCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    public function testAuditCommandHandlesNoFindings(): void
    {
        $this->mock(AuditExecutor::class, function (MockInterface $mock): void {
            $mock->shouldReceive('addAudit')->zeroOrMoreTimes();
            $mock->shouldReceive('execute')->once()->andReturn([]);
        });

        $this->artisan('warden:audit')
            ->expectsOutputToContain('Warden')
            ->expectsOutputToContain('No security issues found.')
            ->assertExitCode(0);
    }

    public function testAuditCommandHandlesFindings(): void
    {
        $findings = [
            [
                'source' => 'composer',
                'title' => 'some/package - High severity vulnerability',
                'severity' => 'high',
                'package' => 'some/package',
            ],
        ];

        $this->mock(AuditExecutor::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('addAudit')->zeroOrMoreTimes();
            $mock->shouldReceive('execute')->once()->andReturn([
                'composer' => [
                    'success' => true,
                    'findings' => $findings,
                    'service' => new \stdClass(),
                ],
            ]);
        });

        $this->artisan('warden:audit', ['--no-notify' => true])
            ->expectsOutputToContain('Warden')
            ->expectsOutputToContain('1 security issue found.')
            ->assertExitCode(1);
    }

    public function testAuditCommandIgnoresConfiguredFindingsBeforeNotifications(): void
    {
        Http::fake();
        Mail::fake();

        config([
            'warden.webhook_url' => 'https://example.com/webhook',
            'warden.email_recipients' => '[email protected]',
            'warden.ignore_findings' => [
                ['source' => 'debug-mode', 'package' => 'laravel/horizon'],
            ],
        ]);

        $findings = [
            [
                'source' => 'debug-mode',
                'title' => 'Development package detected in production',
                'severity' => 'high',
                'package' => 'laravel/horizon',
            ],
        ];

        $this->mock(AuditExecutor::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('addAudit')->zeroOrMoreTimes();
            $mock->shouldReceive('execute')->once()->andReturn([
                'debug-mode' => [
                    'success' => true,
                    'findings' => $findings,
                    'service' => new \stdClass(),
                ],
            ]);
        });

        $this->artisan('warden:audit')
            ->expectsOutputToContain('Warden')
            ->expectsOutputToContain('No security issues found.')
            ->assertExitCode(0);

        Http::assertNothingSent();
        Mail::assertNothingSent();
    }

    public function testAuditCommandSupportsWildcardIgnoreRulesInJsonOutput(): void
    {
        config([
            'warden.ignore_findings' => [
                ['source' => 'debug-mode', 'title' => 'Testing routes*'],
            ],
        ]);

        $findings = [
            [
                'source' => 'debug-mode',
                'title' => 'Testing routes are exposed',
                'severity' => 'high',
                'package' => 'routes',
            ],
        ];

        $this->mock(AuditExecutor::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('addAudit')->zeroOrMoreTimes();
            $mock->shouldReceive('execute')->once()->andReturn([
                'debug-mode' => [
                    'success' => true,
                    'findings' => $findings,
                    'service' => new \stdClass(),
                ],
            ]);
        });

        $this->artisan('warden:audit', ['--output' => 'json'])
            ->expectsOutputToContain('"vulnerabilities_found": 0')
            ->assertExitCode(0);
    }

    public function testAuditCommandFiltersCachedFindingsInSequentialMode(): void
    {
        config([
            'warden.audits.parallel_execution' => false,
            'warden.ignore_findings' => [
                ['source' => 'debug-mode', 'package' => 'laravel/horizon'],
            ],
        ]);

        $this->mock(AuditCacheService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('hasRecentAudit')
                ->times(4)
                ->andReturnUsing(fn (string $auditName): bool => $auditName === 'debug-mode');

            $mock->shouldReceive('getCachedResult')
                ->once()
                ->with('debug-mode')
                ->andReturn([
                    'result' => [
                        [
                            'source' => 'debug-mode',
                            'title' => 'Development package detected in production',
                            'severity' => 'high',
                            'package' => 'laravel/horizon',
                        ],
                    ],
                    'timestamp' => now()->toIso8601String(),
                    'cached' => true,
                ]);
        });

        $this->mock(ComposerAuditService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('getName')->once()->andReturn('composer');
            $mock->shouldReceive('run')->once()->andReturn(true);
            $mock->shouldReceive('getFindings')->once()->andReturn([]);
            $mock->shouldReceive('getAbandonedPackages')->once()->andReturn([]);
        });

        $this->mock(EnvAuditService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('getName')->once()->andReturn('environment');
            $mock->shouldReceive('run')->once()->andReturn(true);
            $mock->shouldReceive('getFindings')->once()->andReturn([]);
        });

        $this->mock(StorageAuditService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('getName')->once()->andReturn('storage');
            $mock->shouldReceive('run')->once()->andReturn(true);
            $mock->shouldReceive('getFindings')->once()->andReturn([]);
        });

        $this->mock(DebugModeAuditService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('getName')->once()->andReturn('debug-mode');
        });

        $this->artisan('warden:audit', ['--no-notify' => true])
            ->expectsOutputToContain('Warden')
            ->expectsOutputToContain('No security issues found.')
            ->assertExitCode(0);
    }
}
