<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\SuppressionService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;

final class SuppressionServiceTest extends TestCase
{
    public function testReviewedSuppressionRemovesOnlyMatchingFinding(): void
    {
        config(['warden.ignore_findings' => [[
            'id' => 'accepted',
            'reason' => 'Reviewed in SEC-123',
            'expires_at' => '2099-01-01',
        ]]]);
        $report = $this->report([
            new Finding('accepted', 'test', 'Accepted', Severity::High, 'Description'),
            new Finding('active', 'test', 'Active', Severity::High, 'Description'),
        ]);

        $auditReport = (new SuppressionService())->apply($report, includeBaseline: false);

        self::assertSame(['active'], array_map(static fn ($finding): string => $finding->id, $auditReport->findings()));
        self::assertCount(1, $auditReport->ignoredFindings);
        self::assertSame([], $auditReport->errors());
    }

    public function testExpiredSuppressionIsAConfigurationError(): void
    {
        config(['warden.ignore_findings' => [[
            'id' => 'accepted',
            'reason' => 'Old review',
            'expires_at' => '2025-01-01',
        ]]]);

        $auditReport = (new SuppressionService())->apply($this->report([]), includeBaseline: false);

        self::assertSame('suppression_expired', $auditReport->errors()[0]->code);
        self::assertSame(2, $auditReport->exitCode('never'));
    }

    public function testBaselineSuppressesOnlyTheExactFingerprint(): void
    {
        $path = sys_get_temp_dir() . '/warden-suppression-' . bin2hex(random_bytes(8)) . '.json';
        $matching = new Finding('legacy', 'test', 'Legacy A', Severity::High, 'Description', package: 'one');
        $different = new Finding('legacy', 'test', 'Legacy B', Severity::High, 'Description', package: 'two');
        file_put_contents($path, json_encode([
            'schema_version' => '1.0.0',
            'findings' => [[
                'id' => $matching->id,
                'fingerprint' => $matching->fingerprint(),
                'reason' => 'Tracked in SEC-123',
                'expires_at' => '2099-01-01',
            ]],
        ], JSON_THROW_ON_ERROR));
        config(['warden.baseline.file' => $path]);

        try {
            $auditReport = (new SuppressionService())->apply($this->report([$matching, $different]));

            self::assertSame($different->fingerprint(), $auditReport->findings()[0]->fingerprint());
            self::assertSame($matching->fingerprint(), $auditReport->ignoredFindings[0]->fingerprint());
        } finally {
            unlink($path);
        }
    }

    /** @param list<Finding> $findings */
    private function report(array $findings): AuditReport
    {
        return new AuditReport(
            new AuditContext(),
            [AuditResult::complete('test', $findings)],
            scannedAt: CarbonImmutable::parse('2026-01-01T00:00:00Z'),
        );
    }
}
