<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\AuditRunner;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use Mockery\MockInterface;

final class WardenBaselineCommandTest extends TestCase
{
    public function testBaselineContainsExactExpiringFingerprints(): void
    {
        $path = sys_get_temp_dir() . '/warden-baseline-' . bin2hex(random_bytes(8)) . '.json';
        $finding = new Finding('test.legacy', 'test', 'Legacy', Severity::Medium, 'Description');
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::complete('test', [$finding])]);
        $this->mock(AuditRunner::class, function (MockInterface $mock) use ($auditReport): void {
            $mock->shouldReceive('run')->once()->andReturn($auditReport);
        });

        try {
            $this->artisan('warden:baseline', [
                '--file' => $path,
                '--reason' => 'Tracked in SEC-123',
                '--expires' => '2099-01-01',
            ])->assertExitCode(0);

            $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
            self::assertSame('1.0.0', $decoded['schema_version']);
            self::assertSame('test.legacy', $decoded['findings'][0]['id']);
            self::assertSame($finding->fingerprint(), $decoded['findings'][0]['fingerprint']);
            self::assertSame('Tracked in SEC-123', $decoded['findings'][0]['reason']);
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }
}
