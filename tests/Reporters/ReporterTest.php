<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Reporters;

use Carbon\CarbonImmutable;
use DOMDocument;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Reporters\GitLabReporter;
use Dgtlss\Warden\Reporters\JsonReporter;
use Dgtlss\Warden\Reporters\JunitReporter;
use Dgtlss\Warden\Reporters\SarifReporter;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ReporterTest extends TestCase
{
    public function testJsonContainsCompleteVersionedContract(): void
    {
        $decoded = json_decode((new JsonReporter())->format($this->report()), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('2.0.0', $decoded['schema_version']);
        self::assertSame('completed', $decoded['run']['status']);
        self::assertSame('reporter.high', $decoded['findings'][0]['id']);
        self::assertArrayHasKey('audits', $decoded);
        self::assertArrayHasKey('errors', $decoded);

        $schema = json_decode(
            (string) file_get_contents(dirname(__DIR__, 2) . '/resources/schemas/warden-report-2.0.0.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        self::assertSame('2.0.0', $schema['properties']['schema_version']['const']);
    }

    #[DataProvider('jsonReporterProvider')]
    public function testStandardJsonReportersProduceParseableContracts(string $reporter, string $versionPath, string $expected): void
    {
        $instance = new $reporter();
        $decoded = json_decode($instance->format($this->report()), true, 512, JSON_THROW_ON_ERROR);
        $value = $decoded;
        foreach (explode('.', $versionPath) as $segment) {
            $value = $value[$segment];
        }

        self::assertSame($expected, $value);
    }

    /** @return iterable<string, array{class-string, string, string}> */
    public static function jsonReporterProvider(): iterable
    {
        yield 'SARIF 2.1.0' => [SarifReporter::class, 'version', '2.1.0'];
        yield 'GitLab 15.2.4' => [GitLabReporter::class, 'version', '15.2.4'];
    }

    public function testJunitIsValidXmlAndRepresentsFindingsAsFailures(): void
    {
        $domDocument = new DOMDocument();

        self::assertTrue($domDocument->loadXML((new JunitReporter())->format($this->report())));
        self::assertSame(1, $domDocument->getElementsByTagName('failure')->length);
    }

    private function report(): AuditReport
    {
        $finding = new Finding(
            'reporter.high',
            'composer',
            'Vulnerable dependency',
            Severity::High,
            'A known vulnerability is present.',
            'Upgrade the package.',
            'vendor/package',
            'https://example.com/advisory',
            'composer.lock',
            metadata: ['affected_versions' => '<2.0'],
        );

        return new AuditReport(
            new AuditContext(),
            [AuditResult::complete('composer', [$finding])],
            scannedAt: CarbonImmutable::parse('2026-01-01T00:00:00Z'),
        );
    }
}
