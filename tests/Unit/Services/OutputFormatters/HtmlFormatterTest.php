<?php

namespace Dgtlss\Warden\Tests\Unit\Services\OutputFormatters;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\OutputFormatters\HtmlFormatter;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\ValueObjects\Remediation;

class HtmlFormatterTest extends TestCase
{
    public function testFormatReturnsValidHtml(): void
    {
        $formatter = new HtmlFormatter();

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
        $this->assertStringContainsString('<!DOCTYPE html>', $output);
        $this->assertStringContainsString('<html', $output);
        $this->assertStringContainsString('</html>', $output);
    }

    public function testFormatContainsTitle(): void
    {
        $formatter = new HtmlFormatter();
        $findings = [];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('Warden Security Audit Report', $output);
    }

    public function testFormatContainsSummarySection(): void
    {
        $formatter = new HtmlFormatter();

        $findings = [
            new Finding(
                source: 'Test',
                package: 'test/package',
                title: 'Critical issue',
                severity: Severity::CRITICAL
            ),
            new Finding(
                source: 'Test',
                package: 'test/package',
                title: 'High issue',
                severity: Severity::HIGH
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('Executive Summary', $output);
        $this->assertStringContainsString('Total Findings', $output);
        $this->assertStringContainsString('Critical', $output);
        $this->assertStringContainsString('High', $output);
    }

    public function testFormatContainsFindingsTable(): void
    {
        $formatter = new HtmlFormatter();

        $findings = [
            new Finding(
                source: 'Composer Audit',
                package: 'vendor/package',
                title: 'Security issue',
                severity: Severity::HIGH,
                cve: 'CVE-2024-0001',
                error: 'This is a security vulnerability'
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('<table', $output);
        $this->assertStringContainsString('vendor/package', $output);
        $this->assertStringContainsString('Security issue', $output);
        $this->assertStringContainsString('CVE-2024-0001', $output);
    }

    public function testFormatGroupsFindingsBySource(): void
    {
        $formatter = new HtmlFormatter();

        $findings = [
            new Finding(
                source: 'Composer Audit',
                package: 'package1',
                title: 'Issue 1',
                severity: Severity::HIGH
            ),
            new Finding(
                source: 'NPM Audit',
                package: 'package2',
                title: 'Issue 2',
                severity: Severity::MEDIUM
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('Composer Audit', $output);
        $this->assertStringContainsString('NPM Audit', $output);
    }

    public function testFormatHandlesEmptyFindings(): void
    {
        $formatter = new HtmlFormatter();
        $findings = [];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('No Security Issues Found', $output);
    }

    public function testFormatIncludesStyles(): void
    {
        $formatter = new HtmlFormatter();
        $findings = [];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('<style>', $output);
        $this->assertStringContainsString('</style>', $output);
    }

    public function testFormatShowsCorrectSeverityCounts(): void
    {
        $formatter = new HtmlFormatter();

        $findings = [
            new Finding(source: 'Test', package: 'p1', title: 'T1', severity: Severity::CRITICAL),
            new Finding(source: 'Test', package: 'p2', title: 'T2', severity: Severity::CRITICAL),
            new Finding(source: 'Test', package: 'p3', title: 'T3', severity: Severity::HIGH),
            new Finding(source: 'Test', package: 'p4', title: 'T4', severity: Severity::MEDIUM),
            new Finding(source: 'Test', package: 'p5', title: 'T5', severity: Severity::LOW),
        ];

        $output = $formatter->format($findings);

        // The HTML should show counts: 2 critical, 1 high, 1 medium, 1 low, 5 total
        $this->assertStringContainsString('summary-number">5</div>', $output); // total
        $this->assertStringContainsString('summary-number">2</div>', $output); // critical
        $this->assertStringContainsString('summary-number">1</div>', $output); // others
    }

    public function testFormatEscapesHtmlInFindings(): void
    {
        $formatter = new HtmlFormatter();

        $findings = [
            new Finding(
                source: 'Test',
                package: '<script>alert("xss")</script>',
                title: 'Test <b>bold</b>',
                severity: Severity::HIGH,
                error: 'Error with <script>tags</script>'
            ),
        ];

        $output = $formatter->format($findings);

        // Should not contain unescaped HTML tags from user input
        $this->assertStringNotContainsString('<script>alert("xss")</script>', $output);
        $this->assertStringContainsString('&lt;script&gt;', $output);
    }

    public function testFormatIncludesRemediationColumn(): void
    {
        $formatter = new HtmlFormatter();

        $findings = [
            new Finding(
                source: 'Test',
                package: 'test/package',
                title: 'Test issue',
                severity: Severity::HIGH
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('<th>Remediation</th>', $output);
    }

    public function testFormatDisplaysRemediationWhenPresent(): void
    {
        $formatter = new HtmlFormatter();

        $remediation = new Remediation(
            description: 'Update the package to fix the vulnerability',
            commands: ['composer update test/package'],
            manualSteps: ['Review the changelog'],
            links: ['https://example.com/advisory'],
            priority: 'high',
        );

        $findings = [
            new Finding(
                source: 'Composer Audit',
                package: 'test/package',
                title: 'Security vulnerability',
                severity: Severity::HIGH,
                remediation: $remediation,
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('Update the package to fix the vulnerability', $output);
        $this->assertStringContainsString('composer update test/package', $output);
        $this->assertStringContainsString('Review the changelog', $output);
        $this->assertStringContainsString('https://example.com/advisory', $output);
    }

    public function testFormatDisplaysPriorityBadge(): void
    {
        $formatter = new HtmlFormatter();

        $remediation = new Remediation(
            description: 'Fix it immediately',
            priority: 'immediate',
        );

        $findings = [
            new Finding(
                source: 'Test',
                package: 'test/package',
                title: 'Critical issue',
                severity: Severity::CRITICAL,
                remediation: $remediation,
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('priority-immediate', $output);
        $this->assertStringContainsString('Immediate', $output);
    }

    public function testFormatShowsNoRemediationPlaceholder(): void
    {
        $formatter = new HtmlFormatter();

        $findings = [
            new Finding(
                source: 'Test',
                package: 'test/package',
                title: 'Test issue',
                severity: Severity::HIGH
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('no-remediation', $output);
    }

    public function testFormatEscapesHtmlInRemediation(): void
    {
        $formatter = new HtmlFormatter();

        $remediation = new Remediation(
            description: '<script>alert("xss")</script>',
            commands: ['<script>malicious</script>'],
            manualSteps: ['<img onerror="alert(1)" src="x">'],
            links: ['https://example.com/<script>'],
        );

        $findings = [
            new Finding(
                source: 'Test',
                package: 'test/package',
                title: 'Test issue',
                severity: Severity::HIGH,
                remediation: $remediation,
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringNotContainsString('<script>alert("xss")</script>', $output);
        $this->assertStringContainsString('&lt;script&gt;', $output);
    }

    public function testFormatRendersRemediationLinks(): void
    {
        $formatter = new HtmlFormatter();

        $remediation = new Remediation(
            description: 'Fix it',
            links: ['https://nvd.nist.gov/vuln/detail/CVE-2024-1234'],
        );

        $findings = [
            new Finding(
                source: 'Test',
                package: 'test/package',
                title: 'Test issue',
                severity: Severity::HIGH,
                remediation: $remediation,
            ),
        ];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('<a href="https://nvd.nist.gov/vuln/detail/CVE-2024-1234"', $output);
        $this->assertStringContainsString('target="_blank"', $output);
        $this->assertStringContainsString('rel="noopener"', $output);
    }

    public function testFormatIncludesRemediationStyles(): void
    {
        $formatter = new HtmlFormatter();
        $findings = [];

        $output = $formatter->format($findings);

        $this->assertStringContainsString('.remediation', $output);
        $this->assertStringContainsString('.priority-badge', $output);
        $this->assertStringContainsString('.priority-immediate', $output);
        $this->assertStringContainsString('.priority-high', $output);
    }
}
