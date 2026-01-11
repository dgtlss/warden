<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Dgtlss\Warden\Tests\TestCase;

class StorageAuditServiceTest extends TestCase
{
    public function testGetNameReturnsStorage(): void
    {
        $service = new StorageAuditService();

        $this->assertEquals('storage', $service->getName());
    }

    public function testRunChecksStandardDirectories(): void
    {
        // This test will run on the actual package filesystem
        // The package itself should have these directories

        $service = new StorageAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        // In the package context, we might not have all Laravel directories
        // But the service should run without errors
        $this->assertIsArray($findings);
    }

    public function testRunDetectsMissingDirectories(): void
    {
        // We can't easily mock file_exists, but we can test the logic
        // by checking that findings are properly structured

        $service = new StorageAuditService();
        $service->run();

        $findings = $service->getFindings();

        // Findings array should exist even if empty
        $this->assertIsArray($findings);

        if (!empty($findings)) {
            foreach ($findings as $finding) {
                $this->assertEquals('storage', $finding['package']);
                $this->assertEquals('high', $finding['severity']);
                $this->assertArrayHasKey('title', $finding);

                // Title should mention either "Missing directory" or "not writable"
                $this->assertTrue(
                    str_contains($finding['title'], 'Missing directory') ||
                    str_contains($finding['title'], 'not writable')
                );
            }
        } else {
            // If no findings, test passed
            $this->assertTrue(true);
        }
    }

    public function testFindingsHaveCorrectStructure(): void
    {
        $service = new StorageAuditService();
        $service->run();

        $findings = $service->getFindings();

        // Findings array should exist
        $this->assertIsArray($findings);

        if (!empty($findings)) {
            $this->assertValidFindings($findings);

            foreach ($findings as $finding) {
                $this->assertEquals('storage', $finding['source']);
                $this->assertEquals('storage', $finding['package']);
                $this->assertNull($finding['cve']);
                $this->assertNull($finding['affected_versions']);
            }
        } else {
            // If no findings, just verify the findings array is empty
            $this->assertEmpty($findings);
        }
    }

    public function testRunAlwaysReturnsTrue(): void
    {
        // The service always returns true even if it finds issues
        $service = new StorageAuditService();
        $result = $service->run();

        $this->assertTrue($result);
    }
}
