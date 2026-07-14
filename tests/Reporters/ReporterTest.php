<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Reporters;

use Carbon\CarbonImmutable;
use DOMDocument;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Reporters\ConsoleReporter;
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
        self::assertSame(1, $decoded['summary']['blocking']);
        self::assertSame(0, $decoded['summary']['advisory']);
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

    public function testConsoleReportGroupsRepeatedFindingsIntoReadableSections(): void
    {
        $first = new Finding(
            'source.secrets.provider-credential',
            'source',
            'Google API key appears to be committed in source',
            Severity::Critical,
            'A credential was detected at app/First.php:10.',
            'Rotate the credential and move it to a secret store.',
            path: 'app/First.php',
            line: 10,
            blocking: false,
            identity: 'first',
        );
        $second = new Finding(
            'source.secrets.provider-credential',
            'source',
            'Google API key appears to be committed in source',
            Severity::Critical,
            'A credential was detected at app/Second.php:20.',
            'Rotate the credential and move it to a secret store.',
            path: 'app/Second.php',
            line: 20,
            blocking: false,
            identity: 'second',
        );
        $auditReport = new AuditReport(
            new AuditContext(),
            [AuditResult::complete('source', [$first, $second])->withDuration(123.4)],
            scannedAt: CarbonImmutable::parse('2026-01-01T00:00:00Z'),
        );

        $output = (new ConsoleReporter())->format($auditReport);

        self::assertStringContainsString('WARDEN 2.0  SECURITY AUDIT', $output);
        self::assertStringContainsString('2 active findings', $output);
        self::assertStringContainsString('CHECK RESULTS', $output);
        self::assertStringContainsString('CHECK                RESULT        SEVERITY', $output);
        self::assertStringContainsString('SOURCE               2 findings    C   2  H   0  M   0  L   0   0 blocking    2 advisory', $output);
        self::assertStringContainsString('SOURCE  2 findings  • C 2', $output);
        self::assertStringContainsString('CRITICAL  2', $output);
        self::assertStringContainsString('· 2 occurrences', $output);
        self::assertStringContainsString('ADVISORY', $output);
        self::assertStringContainsString('app/First.php:10', $output);
        self::assertStringContainsString('app/Second.php:20', $output);
        self::assertSame(1, substr_count($output, 'Google API key appears to be committed in source'));
        self::assertSame(1, substr_count($output, 'Rotate the credential and move it to a secret store.'));
        self::assertStringNotContainsString('A credential was detected at app/First.php:10.', $output);
    }

    public function testConsoleReportMakesPerCheckCountsAndFailuresExplicit(): void
    {
        $composerFinding = new Finding(
            'composer.advisory.example',
            'composer',
            'Vulnerable Composer dependency',
            Severity::High,
            'A dependency is vulnerable.',
        );
        $auditReport = new AuditReport(new AuditContext(), [
            AuditResult::complete('composer', [$composerFinding])->withDuration(334.1),
            AuditResult::complete('npm')->withDuration(155.4),
            AuditResult::failed('source', 'file_too_large', 'main.js is too large.')->withDuration(3426.2),
        ]);

        $output = (new ConsoleReporter())->format($auditReport);

        self::assertStringContainsString('COMPOSER             1 finding     C   0  H   1  M   0  L   0   1 blocking    0 advisory', $output);
        self::assertStringContainsString('NPM                  clean', $output);
        self::assertStringContainsString('SOURCE               incomplete', $output);
        self::assertStringContainsString('SOURCE  file_too_large', $output);
        self::assertStringContainsString('COMPOSER  1 finding  • H 1', $output);

        $rows = array_values(array_filter(
            explode(PHP_EOL, $output),
            static fn (string $line): bool => str_starts_with($line, '✓  COMPOSER')
                || str_starts_with($line, '✓  NPM')
                || str_starts_with($line, '✗  SOURCE'),
        ));
        self::assertCount(3, $rows);
        self::assertSame(strlen($rows[0]), strlen($rows[1]));
        self::assertSame(strlen($rows[0]), strlen($rows[2]));
    }

    public function testAdvisoriesAreSarifNotesAndJunitSkippedCases(): void
    {
        $finding = new Finding('review.me', 'source', 'Review me', Severity::High, 'Advisory only.', blocking: false);
        $auditReport = new AuditReport(new AuditContext(), [AuditResult::complete('source', [$finding])]);
        $sarif = json_decode((new SarifReporter())->format($auditReport), true, 512, JSON_THROW_ON_ERROR);
        $domDocument = new DOMDocument();
        $domDocument->loadXML((new JunitReporter())->format($auditReport));

        self::assertSame('note', $sarif['runs'][0]['results'][0]['level']);
        self::assertFalse($sarif['runs'][0]['results'][0]['properties']['blocking']);
        self::assertSame(1, $domDocument->getElementsByTagName('skipped')->length);
    }

    public function testSarifOmitsRegionWhenFindingHasNoLine(): void
    {
        $sarif = json_decode((new SarifReporter())->format($this->report()), true, 512, JSON_THROW_ON_ERROR);
        $physicalLocation = $sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation'];

        self::assertSame('composer.lock', $physicalLocation['artifactLocation']['uri']);
        self::assertArrayNotHasKey('region', $physicalLocation);
    }

    public function testGitlabTimestampsMatchTheDeclaredSchemaVersion(): void
    {
        $gitlab = json_decode((new GitLabReporter())->format($this->report()), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('15.2.4', $gitlab['version']);
        self::assertSame('2026-01-01T00:00:00', $gitlab['scan']['start_time']);
        self::assertSame('2026-01-01T00:00:00', $gitlab['scan']['end_time']);
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
