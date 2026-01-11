<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\AbstractAuditService;
use Dgtlss\Warden\Tests\TestCase;

class AbstractAuditServiceTest extends TestCase
{
    private TestableAuditService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new TestableAuditService();
    }

    public function testGetFindingsReturnsEmptyArrayByDefault(): void
    {
        $findings = $this->service->getFindings();

        $this->assertIsArray($findings);
        $this->assertEmpty($findings);
    }

    public function testAddFindingAddsToFindings(): void
    {
        $finding = [
            'package' => 'test/package',
            'title' => 'Test vulnerability',
            'severity' => 'high',
        ];

        $this->service->addFinding($finding);

        $findings = $this->service->getFindings();

        $this->assertCount(1, $findings);
        $this->assertEquals('test/package', $findings[0]->package);
        $this->assertEquals('Test vulnerability', $findings[0]->title);
        $this->assertEquals('high', $findings[0]->severity->value);
    }

    public function testAddFindingIncludesSourceAutomatically(): void
    {
        $finding = [
            'package' => 'test/package',
            'title' => 'Test vulnerability',
            'severity' => 'critical',
        ];

        $this->service->addFinding($finding);

        $findings = $this->service->getFindings();

        $this->assertEquals('testable', $findings[0]->source);
    }

    public function testAddMultipleFindings(): void
    {
        $finding1 = [
            'package' => 'package-one',
            'title' => 'Vulnerability One',
            'severity' => 'high',
        ];

        $finding2 = [
            'package' => 'package-two',
            'title' => 'Vulnerability Two',
            'severity' => 'medium',
        ];

        $this->service->addFinding($finding1);
        $this->service->addFinding($finding2);

        $findings = $this->service->getFindings();

        $this->assertCount(2, $findings);
        $this->assertEquals('package-one', $findings[0]->package);
        $this->assertEquals('package-two', $findings[1]->package);
    }

    public function testFindingsAreValid(): void
    {
        $finding = [
            'package' => 'test/package',
            'title' => 'Security issue',
            'severity' => 'low',
            'cve' => 'CVE-2024-1234',
        ];

        $this->service->addFinding($finding);

        $findings = $this->service->getFindings();

        $this->assertCount(1, $findings);
        $this->assertInstanceOf(\Dgtlss\Warden\ValueObjects\Finding::class, $findings[0]);
    }
}

/**
 * Concrete implementation of AbstractAuditService for testing.
 */
class TestableAuditService extends AbstractAuditService
{
    public function run(): bool
    {
        return true;
    }

    public function getName(): string
    {
        return 'testable';
    }

    /**
     * Expose addFinding for testing.
     */
    public function addFinding(\Dgtlss\Warden\ValueObjects\Finding|array $finding): void
    {
        parent::addFinding($finding);
    }
}
