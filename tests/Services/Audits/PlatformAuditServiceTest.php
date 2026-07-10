<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\Services\Audits\PlatformAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;

final class PlatformAuditServiceTest extends TestCase
{
    public function testUnsupportedPlatformsBlockAndSupportedPlatformsPass(): void
    {
        $unsupported = new class extends PlatformAuditService {
            protected function phpVersion(): string { return '8.2.30'; }

            protected function laravelVersion(): string { return '11.0.0'; }
        };
        $auditResult = $unsupported->run(new AuditContext(scannedAt: CarbonImmutable::parse('2027-01-01')));

        self::assertSame(['platform.php.eol', 'platform.laravel.eol'], array_map(static fn ($finding): string => $finding->id, $auditResult->findings));
        self::assertTrue($auditResult->findings[0]->blocking);

        $supported = new class extends PlatformAuditService {
            protected function phpVersion(): string { return '8.5.1'; }

            protected function laravelVersion(): string { return '13.0.0'; }
        };
        $passed = $supported->run(new AuditContext(scannedAt: CarbonImmutable::parse('2026-07-10')));

        self::assertSame([], $passed->findings);
    }

    public function testSecurityOnlyPlatformIsAdvisory(): void
    {
        $service = new class extends PlatformAuditService {
            protected function phpVersion(): string { return '8.3.20'; }

            protected function laravelVersion(): ?string { return null; }
        };
        $auditResult = $service->run(new AuditContext(scannedAt: CarbonImmutable::parse('2026-07-10')));

        self::assertSame('platform.php.security-only', $auditResult->findings[0]->id);
        self::assertFalse($auditResult->findings[0]->blocking);
    }
}
