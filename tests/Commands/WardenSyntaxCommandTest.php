<?php

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\Audits\PhpSyntaxAuditService;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;

class WardenSyntaxCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    public function testSyntaxCommandHandlesNoFindings(): void
    {
        $this->mock(PhpSyntaxAuditService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->once()->andReturn(true);
        });

        $this->artisan('warden:syntax')
            ->expectsOutputToContain('Warden PHP Syntax Audit')
            ->expectsOutputToContain('No PHP syntax errors found.')
            ->assertExitCode(0);
    }

    public function testSyntaxCommandHandlesFindings(): void
    {
        $findings = [
            [
                'title' => 'test.php',
                'description' => 'Parse error: syntax error, unexpected T_STRING',
            ],
        ];

        $this->mock(PhpSyntaxAuditService::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('run')->once()->andReturn(false);
            $mock->shouldReceive('getFindings')->once()->andReturn($findings);
        });

        $this->artisan('warden:syntax')
            ->expectsOutputToContain('Warden PHP Syntax Audit')
            ->expectsOutputToContain('1 syntax error found.')
            ->assertExitCode(1);
    }

    public function testSyntaxCommandHandlesAuditError(): void
    {
        $findings = [
            [
                'title' => 'Error',
                'description' => 'The audit could not be run.',
                'severity' => 'error',
            ],
        ];

        $this->mock(PhpSyntaxAuditService::class, function (MockInterface $mock) use ($findings): void {
            $mock->shouldReceive('run')->once()->andReturn(false);
            $mock->shouldReceive('getFindings')->once()->andReturn($findings);
        });

        $this->artisan('warden:syntax')
            ->expectsOutputToContain('Warden PHP Syntax Audit')
            ->expectsOutputToContain('1 syntax error found.')
            ->assertExitCode(2);
    }
}
