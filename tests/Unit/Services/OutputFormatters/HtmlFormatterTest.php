<?php

namespace Dgtlss\Warden\Tests\Unit\Services\OutputFormatters;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\OutputFormatters\HtmlFormatter;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;

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
}
