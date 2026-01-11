<?php

namespace Dgtlss\Warden\Tests\Unit\Services\OutputFormatters;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\OutputFormatters\SarifFormatter;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;

class SarifFormatterTest extends TestCase
{
    public function testFormatReturnsValidJson(): void
    {
        $formatter = new SarifFormatter();

        $findings = [
            new Finding(
                source: 'Test Audit',
                package: 'test/package',
                title: 'Test vulnerability',
                severity: Severity::HIGH,
                cve: 'CVE-2024-1234',
                affectedVersions: '1.0.0'
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertIsString($output);
        $this->assertNotEmpty($output);

        $decoded = json_decode($output, true);
        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('version', $decoded);
        $this->assertEquals('2.1.0', $decoded['version']);
    }

    public function testFormatContainsSarifSchema(): void
    {
        $formatter = new SarifFormatter();
        $findings = [];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('$schema', $decoded);
        $this->assertStringContainsString('sarif-schema-2.1.0.json', $decoded['$schema']);
    }

    public function testFormatContainsRuns(): void
    {
        $formatter = new SarifFormatter();

        $findings = [
            new Finding(
                source: 'Composer Audit',
                package: 'vendor/package',
                title: 'Security issue',
                severity: Severity::CRITICAL
            ),
        ];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('runs', $decoded);
        $this->assertIsArray($decoded['runs']);
        $this->assertCount(1, $decoded['runs']);
    }

    public function testFormatContainsToolInformation(): void
    {
        $formatter = new SarifFormatter();
        $findings = [];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('tool', $decoded['runs'][0]);
        $this->assertArrayHasKey('driver', $decoded['runs'][0]['tool']);

        $driver = $decoded['runs'][0]['tool']['driver'];
        $this->assertEquals('Warden', $driver['name']);
        $this->assertEquals('1.4.1', $driver['version']);
    }

    public function testFormatMapsFindingsToResults(): void
    {
        $formatter = new SarifFormatter();

        $findings = [
            new Finding(
                source: 'Test Source',
                package: 'test/package',
                title: 'Test Finding',
                severity: Severity::HIGH,
                cve: 'CVE-2024-0001'
            ),
        ];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('results', $decoded['runs'][0]);
        $this->assertCount(1, $decoded['runs'][0]['results']);

        $result = $decoded['runs'][0]['results'][0];
        $this->assertArrayHasKey('ruleId', $result);
        $this->assertArrayHasKey('level', $result);
        $this->assertEquals('error', $result['level']); // HIGH maps to error
    }

    public function testFormatMapsSeverityLevelsCorrectly(): void
    {
        $formatter = new SarifFormatter();

        $testCases = [
            ['severity' => Severity::CRITICAL, 'level' => 'error'],
            ['severity' => Severity::HIGH, 'level' => 'error'],
            ['severity' => Severity::MEDIUM, 'level' => 'warning'],
            ['severity' => Severity::LOW, 'level' => 'note'],
        ];

        foreach ($testCases as $testCase) {
            $findings = [
                new Finding(
                    source: 'Test',
                    package: 'test/package',
                    title: 'Test',
                    severity: $testCase['severity']
                ),
            ];

            $output = $formatter->format($findings);
            $decoded = json_decode($output, true);

            $this->assertEquals(
                $testCase['level'],
                $decoded['runs'][0]['results'][0]['level'],
                "Severity {$testCase['severity']->value} should map to level {$testCase['level']}"
            );
        }
    }

    public function testFormatIncludesRuleDefinitions(): void
    {
        $formatter = new SarifFormatter();

        $findings = [
            new Finding(
                source: 'Test Source',
                package: 'test/package',
                title: 'Test Finding',
                severity: Severity::HIGH
            ),
        ];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('rules', $decoded['runs'][0]['tool']['driver']);
        $this->assertCount(1, $decoded['runs'][0]['tool']['driver']['rules']);

        $rule = $decoded['runs'][0]['tool']['driver']['rules'][0];
        $this->assertArrayHasKey('id', $rule);
        $this->assertArrayHasKey('shortDescription', $rule);
        $this->assertArrayHasKey('fullDescription', $rule);
    }

    public function testFormatHandlesEmptyFindings(): void
    {
        $formatter = new SarifFormatter();
        $findings = [];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('runs', $decoded);
        $this->assertEmpty($decoded['runs'][0]['results']);
        $this->assertEmpty($decoded['runs'][0]['tool']['driver']['rules']);
    }
}
