<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Services\AuditExecutor;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class AuditExecutorTest extends TestCase
{
    public function testThrowableBecomesAuditErrorAndLaterAuditsStillRun(): void
    {
        $broken = new class implements AuditServiceInterface {
            public function getName(): string { return 'broken'; }

            public function run(AuditContext $auditContext): AuditResult { throw new RuntimeException('Boom'); }
        };
        $healthy = new class implements AuditServiceInterface {
            public function getName(): string { return 'healthy'; }

            public function run(AuditContext $auditContext): AuditResult { return AuditResult::complete('healthy'); }
        };

        $results = (new AuditExecutor())->execute(new AuditContext(), [$broken, $healthy]);

        self::assertCount(2, $results);
        self::assertSame('unhandled_exception', $results[0]->errors[0]->code);
        self::assertTrue($results[1]->succeeded());
    }

    public function testMismatchedResultIdentityBecomesExecutionError(): void
    {
        $audit = new class implements AuditServiceInterface {
            public function getName(): string { return 'expected'; }

            public function run(AuditContext $auditContext): AuditResult { return AuditResult::complete('different'); }
        };

        $result = (new AuditExecutor())->execute(new AuditContext(), [$audit])[0];

        self::assertSame('invalid_result', $result->errors[0]->code);
    }
}
