<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Reporters;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Reporters\JsonReporter;
use Dgtlss\Warden\Services\AuditRunner;
use Dgtlss\Warden\Services\ReportFormatterFactory;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Artisan;
use Mockery\MockInterface;
use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Validator;
use PHPUnit\Framework\Attributes\DataProvider;

final class JsonContractTest extends TestCase
{
    #[DataProvider('reportStates')]
    public function testPublicSerializationKeepsTheLegacySchema(string $state): void
    {
        $auditReport = $this->report($state)->withGate('critical');
        $json = json_encode($auditReport, JSON_THROW_ON_ERROR);
        $this->assertContract($json, false);
        self::assertEquals(json_decode($json), json_decode((new JsonReporter())->format($auditReport)));
        foreach ($auditReport->audits as $audit) {
            $decoded = json_decode(json_encode($audit, JSON_THROW_ON_ERROR));
            self::assertFalse(property_exists($decoded, 'coverage'));
            $schema = $this->schema(false);
            $schema->{'$ref'} = '#/definitions/audit';
            self::assertTrue((new Validator())->validate($decoded, $schema)->isValid());
        }

        $extended = $this->assertContract((new JsonReporter(extended: true))->format($auditReport), true);
        self::assertSame('critical', $extended->gate->fail_on);
        self::assertSame($auditReport->exitCode(), $extended->gate->exit_code);
        self::assertEquals(json_decode($json), json_decode((new JsonReporter())->format($auditReport)), 'Extended rendering must not mutate the default contract.');
    }

    #[DataProvider('cliReports')]
    public function testPrimaryAndAdditionalReportsValidateAgainstTheirSelectedSchemas(string $state, string $format, bool $file): void
    {
        $auditReport = $this->report($state);
        if ($state === 'ignored') {
            config(['warden.ignore_findings' => [['id' => 'test.high', 'reason' => 'Accepted test risk', 'expires_at' => '2099-01-01']]]);
            $auditReport = $this->report('findings');
        }

        if ($state === 'configuration') {
            config(['warden.ignore_findings' => [['id' => 'malformed']]]);
            $this->mock(AuditRunner::class, static function (MockInterface $mock): void {
                $mock->shouldNotReceive('run');
            });
        } else {
            $this->mock(AuditRunner::class, static function (MockInterface $mock) use ($auditReport): void {
                $mock->shouldReceive('run')->once()->andReturn($auditReport);
            });
        }

        $root = sys_get_temp_dir() . '/warden-contract-' . bin2hex(random_bytes(8));
        mkdir($root);
        try {
            $exitCode = Artisan::call('warden:audit', [
                '--format' => $format,
                '--output-file' => $file ? $root . '/primary.json' : '-',
                '--fail-on' => 'high',
                '--report' => ['json:' . $root . '/legacy.json', 'json-v2.1:' . $root . '/extended.json'],
            ]);
            self::assertSame(match ($state) { 'findings' => 1, 'incomplete', 'configuration' => 2, default => 0 }, $exitCode);
            $primary = $this->assertContract($file ? file_get_contents($root . '/primary.json') : Artisan::output(), $format === 'json-v2.1');
            $legacy = $this->assertContract(file_get_contents($root . '/legacy.json'), false);
            $extended = $this->assertContract(file_get_contents($root . '/extended.json'), true);
            self::assertEquals($format === 'json-v2.1' ? $extended : $legacy, $primary);
            self::assertEquals($legacy->run, $extended->run);
            self::assertEquals($legacy->summary, $extended->summary);
            self::assertEquals($legacy->findings, $extended->findings);
            self::assertSame($state === 'ignored' ? 1 : 0, $legacy->summary->ignored);
            self::assertSame('high', $extended->gate->fail_on);
            self::assertSame($exitCode, $extended->gate->exit_code);
            if ($state !== 'configuration') {
                self::assertSame(3, $extended->audits[0]->coverage->scanned);
                self::assertNull($extended->audits[1]->coverage);
            }
        } finally {
            foreach (glob($root . '/*') as $path) { unlink($path); }

            rmdir($root);
        }
    }

    public function testInvalidOptionsRemainMachineReadableInBothFormats(): void
    {
        $this->mock(AuditRunner::class, static function (MockInterface $mock): void {
            $mock->shouldNotReceive('run');
        });
        foreach (['json', 'json-v2.1'] as $format) {
            self::assertSame(2, Artisan::call('warden:audit', ['--format' => $format, '--profile' => 'invalid', '--fail-on' => 'high']));
            $data = $this->assertContract(Artisan::output(), $format === 'json-v2.1');
            self::assertSame('invalid_option', $data->errors[0]->code);
            if ($format === 'json-v2.1') {
                self::assertSame(2, $data->gate->exit_code);
                self::assertSame('high', $data->gate->fail_on);
            }
        }
    }

    public function testExtendedGateRespectsEveryThreshold(): void
    {
        foreach (['low' => 1, 'medium' => 1, 'high' => 1, 'critical' => 0, 'never' => 0] as $threshold => $expected) {
            $data = $this->assertContract((new ReportFormatterFactory())->make('json-v2.1')->format($this->report('findings')->withGate($threshold)), true);
            self::assertSame($threshold, $data->gate->fail_on);
            self::assertSame($expected, $data->gate->exit_code);
        }
    }

    public function testLegacySchemaIsUnchangedFromThe21Release(): void
    {
        self::assertSame(
            '960980b5ba26a03dc2fe1f1f1cdec9df71fd2ff399ded40b1d90f85cdbbd892d',
            hash_file('sha256', dirname(__DIR__, 2) . '/resources/schemas/warden-report-2.0.0.json'),
        );
    }

    public function testStrictSchemasRejectUndeclaredFieldsAndRequireExtendedFields(): void
    {
        $data = json_decode((new JsonReporter())->format($this->report('clean')));
        $validator = new Validator();
        $data->gate = (object) ['fail_on' => 'low', 'exit_code' => 0];
        self::assertFalse($validator->validate($data, $this->schema(false))->isValid());
        unset($data->gate);
        $data->audits[0]->coverage = null;
        self::assertFalse($validator->validate($data, $this->schema(false))->isValid());
        $data = json_decode((new JsonReporter(extended: true))->format($this->report('clean')));
        unset($data->gate);
        self::assertFalse($validator->validate($data, $this->schema(true))->isValid());
        $data = json_decode((new JsonReporter(extended: true))->format($this->report('clean')));
        unset($data->audits[0]->coverage);
        self::assertFalse($validator->validate($data, $this->schema(true))->isValid());
    }

    /** @return iterable<string, array{string}> */
    public static function reportStates(): iterable
    {
        foreach (['clean', 'findings', 'ignored', 'incomplete', 'configuration'] as $state) { yield $state => [$state]; }
    }

    /** @return iterable<string, array{string, string, bool}> */
    public static function cliReports(): iterable
    {
        foreach (self::reportStates() as [$state]) {
            foreach (['json', 'json-v2.1'] as $format) {
                foreach ([false, true] as $file) { yield $state . '-' . $format . '-' . ($file ? 'file' : 'stdout') => [$state, $format, $file]; }
            }
        }
    }

    private function report(string $state): AuditReport
    {
        $finding = new Finding('test.high', 'source', 'Synthetic finding', Severity::High, 'Description', path: 'app/Test.php', line: 3);
        $errors = $state === 'incomplete' ? [new AuditError('source', 'unreadable', 'Cannot read source')] : [];
        return new AuditReport(
            new AuditContext(),
            [new AuditResult('source', $state === 'findings' ? [$finding] : [], $errors, 1.25, ['scanned' => 3, 'skipped' => 1, 'errors' => count($errors)]), AuditResult::complete('custom')],
            ignoredFindings: $state === 'ignored' ? [$finding] : [],
            configurationErrors: $state === 'configuration' ? [new AuditError('configuration', 'invalid_option', 'Invalid option')] : [],
            scannedAt: CarbonImmutable::parse('2026-01-01T00:00:00Z'),
        );
    }

    private function schema(bool $extended): object
    {
        $version = $extended ? '2.1.0' : '2.0.0';
        return json_decode(file_get_contents(dirname(__DIR__, 2) . '/resources/schemas/warden-report-' . $version . '.json'), false, 512, JSON_THROW_ON_ERROR);
    }

    private function assertContract(string $json, bool $extended): object
    {
        $data = json_decode($json, false, 512, JSON_THROW_ON_ERROR);
        $validationResult = (new Validator())->validate($data, $this->schema($extended));
        self::assertTrue($validationResult->isValid(), $validationResult->isValid() ? '' : json_encode((new ErrorFormatter())->format($validationResult->error()), JSON_THROW_ON_ERROR));
        self::assertSame($extended ? '2.1.0' : '2.0.0', $data->schema_version);
        self::assertSame($extended, property_exists($data, 'gate'));
        foreach ($data->audits as $audit) { self::assertSame($extended, property_exists($audit, 'coverage')); }

        return $data;
    }
}
