<?php

namespace Dgtlss\Warden\Tests\Unit\ValueObjects;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\Tests\TestCase;

class FindingTest extends TestCase
{
    public function testConstructorCreatesValidFinding(): void
    {
        $finding = new Finding(
            source: 'composer',
            package: 'vendor/package',
            title: 'Test Vulnerability',
            severity: Severity::HIGH,
            cve: 'CVE-2024-1234',
            affectedVersions: '<1.0.0',
            error: null,
        );

        $this->assertEquals('composer', $finding->source);
        $this->assertEquals('vendor/package', $finding->package);
        $this->assertEquals('Test Vulnerability', $finding->title);
        $this->assertSame(Severity::HIGH, $finding->severity);
        $this->assertEquals('CVE-2024-1234', $finding->cve);
        $this->assertEquals('<1.0.0', $finding->affectedVersions);
        $this->assertNull($finding->error);
    }

    public function testConstructorWithOptionalParametersOnly(): void
    {
        $finding = new Finding(
            source: 'npm',
            package: 'test-package',
            title: 'Security Issue',
            severity: Severity::MEDIUM,
        );

        $this->assertEquals('npm', $finding->source);
        $this->assertEquals('test-package', $finding->package);
        $this->assertEquals('Security Issue', $finding->title);
        $this->assertSame(Severity::MEDIUM, $finding->severity);
        $this->assertNull($finding->cve);
        $this->assertNull($finding->affectedVersions);
        $this->assertNull($finding->error);
    }

    public function testFromArrayCreatesValidFinding(): void
    {
        $data = [
            'source' => 'composer',
            'package' => 'vendor/package',
            'title' => 'Test Vulnerability',
            'severity' => 'high',
            'cve' => 'CVE-2024-1234',
            'affected_versions' => '<1.0.0',
        ];

        $finding = Finding::fromArray($data);

        $this->assertEquals('composer', $finding->source);
        $this->assertEquals('vendor/package', $finding->package);
        $this->assertEquals('Test Vulnerability', $finding->title);
        $this->assertSame(Severity::HIGH, $finding->severity);
        $this->assertEquals('CVE-2024-1234', $finding->cve);
        $this->assertEquals('<1.0.0', $finding->affectedVersions);
    }

    public function testFromArrayWithSeverityEnum(): void
    {
        $data = [
            'source' => 'npm',
            'package' => 'test-package',
            'title' => 'Test',
            'severity' => Severity::CRITICAL,
        ];

        $finding = Finding::fromArray($data);

        $this->assertSame(Severity::CRITICAL, $finding->severity);
    }

    public function testFromArrayUsesDefaults(): void
    {
        $finding = Finding::fromArray([]);

        $this->assertEquals('unknown', $finding->source);
        $this->assertEquals('unknown', $finding->package);
        $this->assertEquals('Unknown vulnerability', $finding->title);
        $this->assertSame(Severity::UNKNOWN, $finding->severity);
    }

    public function testToArrayReturnsCorrectStructure(): void
    {
        $finding = new Finding(
            source: 'composer',
            package: 'vendor/package',
            title: 'Test Vulnerability',
            severity: Severity::HIGH,
            cve: 'CVE-2024-1234',
            affectedVersions: '<1.0.0',
        );

        $array = $finding->toArray();

        $this->assertIsArray($array);
        $this->assertArrayHasKey('source', $array);
        $this->assertArrayHasKey('package', $array);
        $this->assertArrayHasKey('title', $array);
        $this->assertArrayHasKey('severity', $array);
        $this->assertArrayHasKey('cve', $array);
        $this->assertArrayHasKey('affected_versions', $array);

        $this->assertEquals('composer', $array['source']);
        $this->assertEquals('vendor/package', $array['package']);
        $this->assertEquals('Test Vulnerability', $array['title']);
        $this->assertEquals('high', $array['severity']);
        $this->assertEquals('CVE-2024-1234', $array['cve']);
        $this->assertEquals('<1.0.0', $array['affected_versions']);
    }

    public function testToArrayOmitsNullValues(): void
    {
        $finding = new Finding(
            source: 'npm',
            package: 'test-package',
            title: 'Test',
            severity: Severity::LOW,
        );

        $array = $finding->toArray();

        $this->assertArrayNotHasKey('cve', $array);
        $this->assertArrayNotHasKey('affected_versions', $array);
        $this->assertArrayNotHasKey('error', $array);
    }

    public function testIsCriticalReturnsTrueForCritical(): void
    {
        $finding = new Finding(
            source: 'test',
            package: 'test',
            title: 'test',
            severity: Severity::CRITICAL,
        );

        $this->assertTrue($finding->isCritical());
    }

    public function testIsCriticalReturnsFalseForOthers(): void
    {
        $finding = new Finding(
            source: 'test',
            package: 'test',
            title: 'test',
            severity: Severity::HIGH,
        );

        $this->assertFalse($finding->isCritical());
    }

    public function testIsHighReturnsTrueForHigh(): void
    {
        $finding = new Finding(
            source: 'test',
            package: 'test',
            title: 'test',
            severity: Severity::HIGH,
        );

        $this->assertTrue($finding->isHigh());
    }

    public function testIsHighReturnsFalseForOthers(): void
    {
        $finding = new Finding(
            source: 'test',
            package: 'test',
            title: 'test',
            severity: Severity::MEDIUM,
        );

        $this->assertFalse($finding->isHigh());
    }

    public function testIsErrorReturnsTrueForErrorSeverity(): void
    {
        $finding = new Finding(
            source: 'test',
            package: 'test',
            title: 'test',
            severity: Severity::ERROR,
        );

        $this->assertTrue($finding->isError());
    }

    public function testIsErrorReturnsTrueWhenErrorMessagePresent(): void
    {
        $finding = new Finding(
            source: 'test',
            package: 'test',
            title: 'test',
            severity: Severity::HIGH,
            error: 'Something went wrong',
        );

        $this->assertTrue($finding->isError());
    }

    public function testIsErrorReturnsFalseForNormalFindings(): void
    {
        $finding = new Finding(
            source: 'test',
            package: 'test',
            title: 'test',
            severity: Severity::HIGH,
        );

        $this->assertFalse($finding->isError());
    }

    public function testSummaryReturnsFormattedString(): void
    {
        $finding = new Finding(
            source: 'composer',
            package: 'vendor/package',
            title: 'Test Vulnerability',
            severity: Severity::HIGH,
        );

        $summary = $finding->summary();

        $this->assertStringContainsString('HIGH', $summary);
        $this->assertStringContainsString('vendor/package', $summary);
        $this->assertStringContainsString('Test Vulnerability', $summary);
        $this->assertStringContainsString('composer', $summary);
    }

    public function testWithCreatesNewInstanceWithModifiedValues(): void
    {
        $original = new Finding(
            source: 'composer',
            package: 'vendor/package',
            title: 'Original Title',
            severity: Severity::LOW,
        );

        $modified = $original->with(
            title: 'Modified Title',
            severity: Severity::CRITICAL,
        );

        // Original should be unchanged
        $this->assertEquals('Original Title', $original->title);
        $this->assertSame(Severity::LOW, $original->severity);

        // Modified should have new values
        $this->assertEquals('Modified Title', $modified->title);
        $this->assertSame(Severity::CRITICAL, $modified->severity);

        // Unchanged values should remain the same
        $this->assertEquals('composer', $modified->source);
        $this->assertEquals('vendor/package', $modified->package);
    }

    public function testWithoutArgumentsReturnsNewInstanceWithSameValues(): void
    {
        $original = new Finding(
            source: 'npm',
            package: 'test-package',
            title: 'Test',
            severity: Severity::MEDIUM,
        );

        $copy = $original->with();

        // Should not be the same instance
        $this->assertNotSame($original, $copy);

        // But should have identical values
        $this->assertEquals($original->source, $copy->source);
        $this->assertEquals($original->package, $copy->package);
        $this->assertEquals($original->title, $copy->title);
        $this->assertSame($original->severity, $copy->severity);
    }
}
