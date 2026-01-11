<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\ConfigAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;

class ConfigAuditServiceTest extends TestCase
{
    public function testGetNameReturnsConfig(): void
    {
        $service = new ConfigAuditService();

        $this->assertEquals('config', $service->getName());
    }

    public function testRunDetectsDebugModeEnabled(): void
    {
        Config::set('app.debug', true);
        Config::set('session.secure', true);

        $service = new ConfigAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $debugFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Debug mode');
        });

        $this->assertCount(1, $debugFindings);

        $debugFinding = reset($debugFindings);
        $this->assertEquals('config', $debugFinding['package']);
        $this->assertEquals('high', $debugFinding['severity']);
    }

    public function testRunPassesWithDebugModeDisabled(): void
    {
        Config::set('app.debug', false);
        Config::set('session.secure', true);

        $service = new ConfigAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        $debugFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Debug mode');
        });

        $this->assertEmpty($debugFindings);
    }

    public function testRunDetectsInsecureSessionCookies(): void
    {
        Config::set('app.debug', false);
        Config::set('session.secure', false);

        $service = new ConfigAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $sessionFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Session cookies');
        });

        $this->assertCount(1, $sessionFindings);

        $sessionFinding = reset($sessionFindings);
        $this->assertEquals('config', $sessionFinding['package']);
        $this->assertEquals('low', $sessionFinding['severity']);
    }

    public function testRunPassesWithSecureSessionCookies(): void
    {
        Config::set('app.debug', false);
        Config::set('session.secure', true);

        $service = new ConfigAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        $sessionFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Session cookies');
        });

        $this->assertEmpty($sessionFindings);
    }

    public function testRunDetectsMultipleIssues(): void
    {
        Config::set('app.debug', true);
        Config::set('session.secure', false);

        $service = new ConfigAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertGreaterThanOrEqual(2, count($findings));

        // Should have both debug mode and session security findings
        $debugFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Debug mode');
        });

        $sessionFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Session cookies');
        });

        $this->assertNotEmpty($debugFindings);
        $this->assertNotEmpty($sessionFindings);
    }

    public function testRunAlwaysReturnsTrue(): void
    {
        // The service always returns true even if it finds issues
        Config::set('app.debug', true);
        Config::set('session.secure', false);

        $service = new ConfigAuditService();
        $result = $service->run();

        $this->assertTrue($result);
    }

    public function testFindingsHaveCorrectStructure(): void
    {
        Config::set('app.debug', true);

        $service = new ConfigAuditService();
        $service->run();

        $findings = $service->getFindings();

        $this->assertNotEmpty($findings);
        $this->assertValidFindings($findings);

        foreach ($findings as $finding) {
            $this->assertEquals('config', $finding['source']);
            $this->assertEquals('config', $finding['package']);
            $this->assertNull($finding['cve']);
            $this->assertNull($finding['affected_versions']);
        }
    }
}
