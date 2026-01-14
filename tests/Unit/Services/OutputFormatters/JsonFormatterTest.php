<?php

namespace Dgtlss\Warden\Tests\Unit\Services\OutputFormatters;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\OutputFormatters\JsonFormatter;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;

class JsonFormatterTest extends TestCase
{
    public function testFormatReturnsJsonWithSummaryAndFindings(): void
    {
        $formatter = new JsonFormatter();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'High severity vulnerability',
                severity: Severity::HIGH,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
        ];

        $result = $formatter->format($findings, ['trigger' => 'manual']);
        $data = json_decode($result, true);

        $this->assertIsArray($data);
        $this->assertArrayHasKey('metadata', $data);
        $this->assertArrayHasKey('summary', $data);
        $this->assertArrayHasKey('findings', $data);
        $this->assertEquals(1, $data['metadata']['total_findings']);
        $this->assertEquals('manual', $data['metadata']['trigger']);
        $this->assertEquals(1, $data['summary']['high']);
        $this->assertEquals('https://www.cve.org/CVERecord?id=CVE-2024-1234', $data['findings'][0]['cve_url']);
    }

    public function testFormatForCiDefaultsToGeneric(): void
    {
        $formatter = new JsonFormatter();

        $result = $formatter->formatForCI([], 'unknown');
        $data = json_decode($result, true);

        $this->assertIsArray($data);
        $this->assertArrayHasKey('metadata', $data);
        $this->assertArrayHasKey('summary', $data);
        $this->assertArrayHasKey('findings', $data);
    }

    public function testFormatForGitHubIncludesAnnotations(): void
    {
        $formatter = new JsonFormatter();

        $findings = [
            new Finding(
                source: 'npm',
                package: 'test/npm',
                title: 'Moderate vulnerability',
                severity: Severity::MEDIUM,
                affectedVersions: '<2.0',
            ),
        ];

        $result = $formatter->formatForCI($findings, 'github');
        $data = json_decode($result, true);

        $this->assertIsArray($data);
        $this->assertArrayHasKey('annotations', $data);
        $this->assertArrayHasKey('summary', $data);
        $this->assertEquals('Security Vulnerability', $data['annotations'][0]['title']);
    }

    public function testFormatForGitLabIncludesVulnerabilities(): void
    {
        $formatter = new JsonFormatter();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Critical vulnerability',
                severity: Severity::CRITICAL,
                cve: 'CVE-2024-1234',
                affectedVersions: '<1.0',
            ),
        ];

        $result = $formatter->formatForCI($findings, 'gitlab');
        $data = json_decode($result, true);

        $this->assertIsArray($data);
        $this->assertEquals('14.0.0', $data['version']);
        $this->assertNotEmpty($data['vulnerabilities']);
        $this->assertEquals('dependency_scanning', $data['vulnerabilities'][0]['category']);
    }

    public function testFormatForJenkinsIncludesIssues(): void
    {
        $formatter = new JsonFormatter();

        $findings = [
            new Finding(
                source: 'composer',
                package: 'test/package',
                title: 'Low vulnerability',
                severity: Severity::LOW,
                affectedVersions: '<1.0',
            ),
        ];

        $result = $formatter->formatForCI($findings, 'jenkins');
        $data = json_decode($result, true);

        $this->assertIsArray($data);
        $this->assertArrayHasKey('issues', $data);
        $this->assertArrayHasKey('_class', $data);
        $this->assertEquals('io.jenkins.plugins.analysis.core.restapi.ReportApi', $data['_class']);
    }
}
