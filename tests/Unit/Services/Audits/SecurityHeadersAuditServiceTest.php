<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\SecurityHeadersAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;

class SecurityHeadersAuditServiceTest extends TestCase
{
    public function testGetNameReturnsSecurityHeaders(): void
    {
        $service = new SecurityHeadersAuditService();

        $this->assertEquals('Security Headers', $service->getName());
    }

    public function testRunDetectsMissingSecurityHeaders(): void
    {
        Config::set('app.middleware', []);
        Config::set('app.env', 'production');

        $service = new SecurityHeadersAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        // Should detect missing security headers
        $headerFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'Missing security header');
        });

        $this->assertNotEmpty($headerFindings);
    }

    public function testRunPassesWithSecurityHeadersConfigured(): void
    {
        Config::set('app.middleware', [
            'Illuminate\Http\Middleware\HandleCors',
        ]);
        Config::set('app.env', 'production');

        $service = new SecurityHeadersAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        // Should pass with middleware configured
        $this->assertEmpty($findings);
    }

    public function testRunSkipsProductionOnlyHeadersInDevelopment(): void
    {
        Config::set('app.middleware', []);
        Config::set('app.env', 'local');

        $service = new SecurityHeadersAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        // Should not detect HSTS in non-production
        $hstsFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'Strict-Transport-Security');
        });

        $this->assertEmpty($hstsFindings);
    }
}
