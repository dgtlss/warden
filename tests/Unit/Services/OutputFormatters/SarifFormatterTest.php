<?php

namespace Dgtlss\Warden\Tests\Unit\Services\OutputFormatters;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\OutputFormatters\SarifFormatter;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\ValueObjects\Remediation;

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

    public function testFormatIncludesFixesWhenRemediationPresent(): void
    {
        $formatter = new SarifFormatter();

        $remediation = new Remediation(
            description: 'Update the package to fix the vulnerability',
            commands: ['composer update vendor/package'],
            manualSteps: ['Review the changelog'],
            links: ['https://example.com/advisory'],
            priority: 'high',
        );

        $findings = [
            new Finding(
                source: 'Composer Audit',
                package: 'vendor/package',
                title: 'Security vulnerability',
                severity: Severity::HIGH,
                remediation: $remediation,
            ),
        ];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $result = $decoded['runs'][0]['results'][0];

        $this->assertArrayHasKey('fixes', $result);
        $this->assertCount(1, $result['fixes']);
        $this->assertArrayHasKey('description', $result['fixes'][0]);
        $this->assertStringContainsString('Update the package', $result['fixes'][0]['description']['text']);
    }

    public function testFormatIncludesCommandsInFixes(): void
    {
        $formatter = new SarifFormatter();

        $remediation = new Remediation(
            description: 'Fix the issue',
            commands: ['composer update vendor/package', 'composer audit'],
        );

        $findings = [
            new Finding(
                source: 'Test',
                package: 'vendor/package',
                title: 'Test issue',
                severity: Severity::HIGH,
                remediation: $remediation,
            ),
        ];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $fixDescription = $decoded['runs'][0]['results'][0]['fixes'][0]['description']['text'];

        $this->assertStringContainsString('composer update vendor/package', $fixDescription);
        $this->assertStringContainsString('composer audit', $fixDescription);
    }

    public function testFormatIncludesManualStepsInFixes(): void
    {
        $formatter = new SarifFormatter();

        $remediation = new Remediation(
            description: 'Fix the issue',
            manualSteps: ['Step 1: Review changes', 'Step 2: Test application'],
        );

        $findings = [
            new Finding(
                source: 'Test',
                package: 'vendor/package',
                title: 'Test issue',
                severity: Severity::HIGH,
                remediation: $remediation,
            ),
        ];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $fixDescription = $decoded['runs'][0]['results'][0]['fixes'][0]['description']['text'];

        $this->assertStringContainsString('Manual Steps', $fixDescription);
        $this->assertStringContainsString('Review changes', $fixDescription);
        $this->assertStringContainsString('Test application', $fixDescription);
    }

    public function testFormatIncludesLinksInFixes(): void
    {
        $formatter = new SarifFormatter();

        $remediation = new Remediation(
            description: 'Fix the issue',
            links: ['https://example.com/advisory', 'https://nvd.nist.gov/vuln/CVE-2024-1234'],
        );

        $findings = [
            new Finding(
                source: 'Test',
                package: 'vendor/package',
                title: 'Test issue',
                severity: Severity::HIGH,
                remediation: $remediation,
            ),
        ];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $fixDescription = $decoded['runs'][0]['results'][0]['fixes'][0]['description']['text'];

        $this->assertStringContainsString('References', $fixDescription);
        $this->assertStringContainsString('https://example.com/advisory', $fixDescription);
        $this->assertStringContainsString('https://nvd.nist.gov/vuln/CVE-2024-1234', $fixDescription);
    }

    public function testFormatDoesNotIncludeFixesWhenNoRemediation(): void
    {
        $formatter = new SarifFormatter();

        $findings = [
            new Finding(
                source: 'Test',
                package: 'vendor/package',
                title: 'Test issue',
                severity: Severity::HIGH,
            ),
        ];

        $output = $formatter->format($findings);
        $decoded = json_decode($output, true);

        $result = $decoded['runs'][0]['results'][0];

        $this->assertArrayNotHasKey('fixes', $result);
    }
}
