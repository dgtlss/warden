<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Data\AuditRunReport;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\AuditManager;
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
                'rule_id' => 'CVE-2026-0001',
                'category' => 'dependency',
                'severity' => 'high',
                'package' => 'some/package',
                'description' => 'some/package - High severity vulnerability',
                'fingerprint' => hash('sha256', 'some/package'),
                'references' => [],
                'file' => 'composer.lock',
                'line' => 1,
                'remediation' => null,
            ],
        ];

        $this->mock(AuditManager::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('run')->once()->andReturn(new AuditRunReport(
                results: [],
                findings: $findings,
                suppressedFindings: [],
                abandonedPackages: [],
                hasFailures: false,
                durationMs: 0.0,
                profile: 'legacy',
                metadata: []
            ));
        });

        $this->artisan('warden:audit', ['--no-notify' => true])
            ->expectsOutputToContain('Warden')
            ->expectsOutputToContain('1 security issue found.')
            ->assertExitCode(1);
    }

    public function testAuditCommandSuggestsResolveForResolvableFindings(): void
    {
        $findings = [
            [
                'source' => 'composer',
                'title' => 'Upgrade some/package',
                'rule_id' => 'CVE-2026-1111',
                'category' => 'dependency',
                'severity' => 'high',
                'package' => 'some/package',
                'description' => 'Upgrade some/package',
                'fingerprint' => hash('sha256', 'resolve'),
                'references' => [],
                'file' => 'composer.lock',
                'line' => 1,
                'remediation' => null,
                'resolvable' => true,
                'resolver_type' => 'composer',
                'is_direct_dependency' => true,
                'is_dev_dependency' => false,
                'declared_constraint' => '^1.0',
                'installed_version' => '1.0.0',
            ],
        ];

        $this->mock(AuditManager::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('run')->once()->andReturn(new AuditRunReport(
                results: [],
                findings: $findings,
                suppressedFindings: [],
                abandonedPackages: [],
                hasFailures: false,
                durationMs: 0.0,
                profile: 'legacy',
                metadata: []
            ));
        });

        $this->artisan('warden:audit', ['--no-notify' => true])
            ->expectsOutputToContain('Resolvable dependency issues detected. Next step: php artisan warden:resolve --source=composer')
            ->assertExitCode(1);
    }
}
