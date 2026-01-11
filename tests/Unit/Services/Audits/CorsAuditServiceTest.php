<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\CorsAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;

class CorsAuditServiceTest extends TestCase
{
    public function testGetNameReturnsCorsConfiguration(): void
    {
        $service = new CorsAuditService();

        $this->assertEquals('CORS Configuration', $service->getName());
    }

    public function testRunDetectsWildcardOriginInProduction(): void
    {
        Config::set('cors.allowed_origins', ['*']);
        Config::set('cors.supports_credentials', false);
        Config::set('cors.allowed_methods', ['GET', 'POST']);
        Config::set('cors.allowed_headers', ['Content-Type']);
        Config::set('app.env', 'production');

        $service = new CorsAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $wildcardFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'Wildcard CORS origin');
        });

        $this->assertCount(1, $wildcardFindings);

        $finding = reset($wildcardFindings);
        $this->assertEquals('high', $finding->severity->value);
    }

    public function testRunDetectsCredentialsWithWildcard(): void
    {
        Config::set('cors.allowed_origins', ['*']);
        Config::set('cors.supports_credentials', true);
        Config::set('cors.allowed_methods', ['GET', 'POST']);
        Config::set('cors.allowed_headers', ['Content-Type']);
        Config::set('app.env', 'local');

        $service = new CorsAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $credentialFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'Credentials enabled with wildcard');
        });

        $this->assertCount(1, $credentialFindings);

        $finding = reset($credentialFindings);
        $this->assertEquals('critical', $finding->severity->value);
    }

    public function testRunDetectsWildcardMethods(): void
    {
        Config::set('cors.allowed_origins', ['https://example.com']);
        Config::set('cors.supports_credentials', false);
        Config::set('cors.allowed_methods', ['*']);
        Config::set('cors.allowed_headers', ['Content-Type']);
        Config::set('app.env', 'production');

        $service = new CorsAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $methodFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'All HTTP methods allowed');
        });

        $this->assertCount(1, $methodFindings);

        $finding = reset($methodFindings);
        $this->assertEquals('medium', $finding->severity->value);
    }

    public function testRunDetectsDangerousMethods(): void
    {
        Config::set('cors.allowed_origins', ['https://example.com']);
        Config::set('cors.supports_credentials', false);
        Config::set('cors.allowed_methods', ['GET', 'POST', 'TRACE']);
        Config::set('cors.allowed_headers', ['Content-Type']);
        Config::set('app.env', 'production');

        $service = new CorsAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $dangerousMethodFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'Dangerous HTTP methods');
        });

        $this->assertCount(1, $dangerousMethodFindings);

        $finding = reset($dangerousMethodFindings);
        $this->assertEquals('medium', $finding->severity->value);
    }

    public function testRunDetectsWildcardHeaders(): void
    {
        Config::set('cors.allowed_origins', ['https://example.com']);
        Config::set('cors.supports_credentials', false);
        Config::set('cors.allowed_methods', ['GET', 'POST']);
        Config::set('cors.allowed_headers', ['*']);
        Config::set('app.env', 'production');

        $service = new CorsAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $headerFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'All headers allowed');
        });

        $this->assertCount(1, $headerFindings);

        $finding = reset($headerFindings);
        $this->assertEquals('low', $finding->severity->value);
    }

    public function testRunPassesWithSecureConfiguration(): void
    {
        Config::set('cors.allowed_origins', ['https://example.com']);
        Config::set('cors.supports_credentials', true);
        Config::set('cors.allowed_methods', ['GET', 'POST', 'PUT', 'DELETE']);
        Config::set('cors.allowed_headers', ['Content-Type', 'Authorization']);
        Config::set('app.env', 'production');

        $service = new CorsAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertEmpty($findings);
    }
}
