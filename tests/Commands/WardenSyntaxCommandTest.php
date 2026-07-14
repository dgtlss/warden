<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\Audits\PhpSyntaxAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use Mockery\MockInterface;

final class WardenSyntaxCommandTest extends TestCase
{
    public function testCleanSyntaxExitsZero(): void
    {
        $this->mock(PhpSyntaxAuditService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('run')->once()->andReturn(AuditResult::complete('php-syntax'));
        });

        $this->artisan('warden:syntax')
            ->expectsOutputToContain('No PHP syntax errors found.')
            ->assertExitCode(0);
    }

    public function testSyntaxFindingExitsOne(): void
    {
        $finding = new Finding('quality.php.syntax', 'php-syntax', 'Syntax error', Severity::High, 'Parse error', path: 'app/Broken.php');
        $this->mock(PhpSyntaxAuditService::class, function (MockInterface $mock) use ($finding): void {
            $mock->shouldReceive('run')->once()->andReturn(AuditResult::complete('php-syntax', [$finding]));
        });

        $this->artisan('warden:syntax')
            ->expectsOutputToContain('app/Broken.php: Parse error')
            ->assertExitCode(1);
    }

    public function testAuditErrorIsDisplayedAndExitsTwo(): void
    {
        $auditError = new AuditError('php-syntax', 'timeout', 'PHP syntax analysis timed out.');
        $this->mock(PhpSyntaxAuditService::class, function (MockInterface $mock) use ($auditError): void {
            $mock->shouldReceive('run')->once()->andReturn(new AuditResult('php-syntax', errors: [$auditError]));
        });

        $this->artisan('warden:syntax')
            ->expectsOutputToContain('timeout: PHP syntax analysis timed out.')
            ->assertExitCode(2);
    }
}
