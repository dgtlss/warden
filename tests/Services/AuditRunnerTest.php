<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services;

use Dgtlss\Warden\Services\AuditRunner;
use Dgtlss\Warden\Services\Audits\SupplyChainAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use RuntimeException;

final class AuditRunnerTest extends TestCase
{
    public function testBuiltInConstructionFailureBecomesAConfigurationError(): void
    {
        $this->app->bind(SupplyChainAuditService::class, static fn (): never => throw new RuntimeException('fixture construction failed'));

        $auditReport = $this->app->make(AuditRunner::class)->run(new AuditContext());

        self::assertSame('builtin_audit_initialization_failed', $auditReport->errors()[0]->code);
        self::assertStringContainsString(SupplyChainAuditService::class, $auditReport->errors()[0]->message);
        self::assertSame(2, $auditReport->exitCode('never'));
    }
}
