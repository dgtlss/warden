<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\FilePermissionsAuditService;
use Dgtlss\Warden\Tests\TestCase;

class FilePermissionsAuditServiceTest extends TestCase
{
    public function testGetNameReturnsFilePermissions(): void
    {
        $service = new FilePermissionsAuditService();

        $this->assertEquals('File Permissions', $service->getName());
    }

    public function testRunReturnsBoolean(): void
    {
        $service = new FilePermissionsAuditService();
        $result = $service->run();

        $this->assertIsBool($result);
    }

    public function testGetFindingsReturnsArray(): void
    {
        $service = new FilePermissionsAuditService();
        $service->run();

        $findings = $service->getFindings();

        $this->assertIsArray($findings);
    }

    public function testFindingsAreTypeOfFinding(): void
    {
        $service = new FilePermissionsAuditService();
        $service->run();

        $findings = $service->getFindings();

        $this->assertIsArray($findings);

        if (count($findings) > 0) {
            foreach ($findings as $finding) {
                $this->assertInstanceOf(\Dgtlss\Warden\ValueObjects\Finding::class, $finding);
                $this->assertInstanceOf(\Dgtlss\Warden\Enums\Severity::class, $finding->severity);
                $this->assertIsString($finding->package);
                $this->assertIsString($finding->title);
            }
        } else {
            // If no findings, that's fine - just assert array is empty
            $this->assertEmpty($findings);
        }
    }
}
