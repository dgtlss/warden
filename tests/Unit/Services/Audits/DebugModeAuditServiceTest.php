<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;

class DebugModeAuditServiceTest extends TestCase
{
    public function testGetNameReturnsDebugMode(): void
    {
        $service = new DebugModeAuditService();

        $this->assertEquals('debug-mode', $service->getName());
    }

    public function testRunDetectsDebugModeInProduction(): void
    {
        Config::set('app.env', 'production');
        Config::set('app.debug', true);

        $service = new DebugModeAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $debugFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Debug mode is enabled in production');
        });

        $this->assertCount(1, $debugFindings);

        $debugFinding = reset($debugFindings);
        $this->assertEquals('app-config', $debugFinding['package']);
        $this->assertEquals('critical', $debugFinding['severity']);
    }

    public function testRunPassesWithDebugModeDisabledInProduction(): void
    {
        Config::set('app.env', 'production');
        Config::set('app.debug', false);

        $service = new DebugModeAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        $debugFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Debug mode is enabled in production');
        });

        $this->assertEmpty($debugFindings);
    }

    public function testRunAllowsDebugModeInNonProduction(): void
    {
        Config::set('app.env', 'local');
        Config::set('app.debug', true);

        $service = new DebugModeAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        $debugFindings = array_filter($findings, function ($finding) {
            return str_contains($finding['title'], 'Debug mode is enabled in production');
        });

        $this->assertEmpty($debugFindings);
    }

    public function testRunAlwaysReturnsTrue(): void
    {
        Config::set('app.env', 'production');
        Config::set('app.debug', true);

        $service = new DebugModeAuditService();
        $result = $service->run();

        $this->assertTrue($result);
    }

    public function testFindingsHaveCorrectStructure(): void
    {
        Config::set('app.env', 'production');
        Config::set('app.debug', true);

        $service = new DebugModeAuditService();
        $service->run();

        $findings = $service->getFindings();

        if (!empty($findings)) {
            foreach ($findings as $finding) {
                $this->assertArrayHasKey('package', $finding);
                $this->assertArrayHasKey('title', $finding);
                $this->assertArrayHasKey('severity', $finding);
                $this->assertArrayHasKey('source', $finding);
                $this->assertEquals('debug-mode', $finding['source']);
                $this->assertNull($finding['cve']);
                $this->assertNull($finding['affected_versions']);
            }
        }
    }
}
