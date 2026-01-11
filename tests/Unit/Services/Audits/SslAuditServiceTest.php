<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\SslAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;

class SslAuditServiceTest extends TestCase
{
    public function testGetNameReturnsSslTlsConfiguration(): void
    {
        $service = new SslAuditService();

        $this->assertEquals('SSL/TLS Configuration', $service->getName());
    }

    public function testRunDetectsHttpInProduction(): void
    {
        Config::set('app.url', 'http://example.com');
        Config::set('app.env', 'production');
        Config::set('session.secure', true);
        Config::set('session.http_only', true);
        Config::set('session.same_site', 'lax');

        $service = new SslAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $httpsFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'HTTPS not enforced');
        });

        $this->assertCount(1, $httpsFindings);

        $finding = reset($httpsFindings);
        $this->assertEquals('critical', $finding->severity->value);
    }

    public function testRunDetectsInsecureSessionCookie(): void
    {
        Config::set('app.url', 'https://example.com');
        Config::set('app.env', 'production');
        Config::set('session.secure', false);
        Config::set('session.http_only', true);
        Config::set('session.same_site', 'lax');

        $service = new SslAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $secureFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'not marked as secure');
        });

        $this->assertCount(1, $secureFindings);

        $finding = reset($secureFindings);
        $this->assertEquals('high', $finding->severity->value);
    }

    public function testRunDetectsNonHttpOnlyCookie(): void
    {
        Config::set('app.url', 'https://example.com');
        Config::set('app.env', 'production');
        Config::set('session.secure', true);
        Config::set('session.http_only', false);
        Config::set('session.same_site', 'lax');

        $service = new SslAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $httpOnlyFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'accessible via JavaScript');
        });

        $this->assertCount(1, $httpOnlyFindings);

        $finding = reset($httpOnlyFindings);
        $this->assertEquals('medium', $finding->severity->value);
    }

    public function testRunDetectsInvalidSameSite(): void
    {
        Config::set('app.url', 'https://example.com');
        Config::set('app.env', 'production');
        Config::set('session.secure', true);
        Config::set('session.http_only', true);
        Config::set('session.same_site', 'invalid');

        $service = new SslAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $sameSiteFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'Invalid SameSite');
        });

        $this->assertCount(1, $sameSiteFindings);

        $finding = reset($sameSiteFindings);
        $this->assertEquals('medium', $finding->severity->value);
    }

    public function testRunDetectsMixedContent(): void
    {
        Config::set('app.url', 'https://example.com');
        Config::set('app.asset_url', 'http://cdn.example.com');
        Config::set('app.env', 'production');
        Config::set('session.secure', true);
        Config::set('session.http_only', true);
        Config::set('session.same_site', 'lax');

        $service = new SslAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $mixedContentFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'Mixed content');
        });

        $this->assertCount(1, $mixedContentFindings);

        $finding = reset($mixedContentFindings);
        $this->assertEquals('high', $finding->severity->value);
    }

    public function testRunPassesWithSecureConfiguration(): void
    {
        Config::set('app.url', 'https://example.com');
        Config::set('app.asset_url', '');
        Config::set('app.env', 'production');
        Config::set('session.secure', true);
        Config::set('session.http_only', true);
        Config::set('session.same_site', 'lax');

        $service = new SslAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertEmpty($findings);
    }

    public function testRunAllowsHttpInDevelopment(): void
    {
        Config::set('app.url', 'http://localhost');
        Config::set('app.env', 'local');
        Config::set('session.secure', false);
        Config::set('session.http_only', true);
        Config::set('session.same_site', 'lax');

        $service = new SslAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        // HTTP is allowed in non-production
        $httpsFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'HTTPS not enforced');
        });

        $this->assertEmpty($httpsFindings);
    }
}
