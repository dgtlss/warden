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
    public function testRegisteredInactiveAuditIsKnownForOnlyAndSkip(): void
    {
        config(['warden.custom_audits' => [InactiveAudit::class]]);
        $auditRunner = $this->app->make(AuditRunner::class);
        self::assertContains('inactive', $auditRunner->availableAuditIds());
        $auditReport = $auditRunner->run(new AuditContext(only: ['inactive']));
        self::assertSame([], $auditReport->errors());
        self::assertCount(1, $auditReport->audits);
        self::assertSame(1, $auditReport->audits[0]->coverage['skipped']);
        $skip = $auditRunner->run(new AuditContext(only: ['source'], skip: ['inactive']));
        self::assertNotContains('unknown_audit', array_column($skip->errors(), 'code'));
        config(['warden.custom_audits' => [InactiveAudit::class, InactiveAudit::class]]);
        self::assertSame('duplicate_audit_id', $auditRunner->run(new AuditContext(only: ['inactive']))->errors()[0]->code);
    }

    public function testBuiltInConstructionFailureBecomesAConfigurationError(): void
    {
        $this->app->bind(SupplyChainAuditService::class, static fn (): never => throw new RuntimeException('fixture construction failed'));

        $auditReport = $this->app->make(AuditRunner::class)->run(new AuditContext());

        self::assertSame('builtin_audit_initialization_failed', $auditReport->errors()[0]->code);
        self::assertStringContainsString(SupplyChainAuditService::class, $auditReport->errors()[0]->message);
        self::assertSame(2, $auditReport->exitCode('never'));
    }
}

final class InactiveAudit implements \Dgtlss\Warden\Contracts\CustomAudit
{
    public function getName(): string { return 'inactive'; }

    public function getDescription(): string { return 'Inactive synthetic audit'; }

    public function shouldRun(AuditContext $auditContext): bool { return false; }

    public function run(AuditContext $auditContext): \Dgtlss\Warden\ValueObjects\AuditResult { throw new RuntimeException('Inactive audit must not run'); }
}
