<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\DatabaseSecurityAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Config;

class DatabaseSecurityAuditServiceTest extends TestCase
{
    public function testGetNameReturnsDatabaseSecurity(): void
    {
        $service = new DatabaseSecurityAuditService();

        $this->assertEquals('Database Security', $service->getName());
    }

    public function testRunDetectsNoPassword(): void
    {
        Config::set('database.default', 'mysql');
        Config::set('database.connections.mysql.password', '');
        Config::set('database.connections.mysql.host', 'localhost');
        Config::set('app.env', 'production');

        $service = new DatabaseSecurityAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $passwordFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'no password');
        });

        $this->assertCount(1, $passwordFindings);

        $finding = reset($passwordFindings);
        $this->assertEquals('critical', $finding->severity->value);
    }

    public function testRunDetectsWeakPassword(): void
    {
        Config::set('database.default', 'mysql');
        Config::set('database.connections.mysql.password', 'password');
        Config::set('database.connections.mysql.host', 'localhost');
        Config::set('app.env', 'production');

        $service = new DatabaseSecurityAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $weakPasswordFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'Weak database password');
        });

        $this->assertCount(1, $weakPasswordFindings);

        $finding = reset($weakPasswordFindings);
        $this->assertEquals('critical', $finding->severity->value);
    }

    public function testRunDetectsShortPassword(): void
    {
        Config::set('database.default', 'mysql');
        Config::set('database.connections.mysql.password', 'short123');
        Config::set('database.connections.mysql.host', 'localhost');
        Config::set('app.env', 'production');

        $service = new DatabaseSecurityAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $shortPasswordFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'too short');
        });

        $this->assertCount(1, $shortPasswordFindings);

        $finding = reset($shortPasswordFindings);
        $this->assertEquals('high', $finding->severity->value);
    }

    public function testRunDetectsPublicHost(): void
    {
        Config::set('database.default', 'mysql');
        Config::set('database.connections.mysql.password', 'securepassword123456');
        Config::set('database.connections.mysql.host', '0.0.0.0');
        Config::set('app.env', 'production');

        $service = new DatabaseSecurityAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $hostFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'exposed to public network');
        });

        $this->assertCount(1, $hostFindings);

        $finding = reset($hostFindings);
        $this->assertEquals('critical', $finding->severity->value);
    }

    public function testRunDetectsDefaultUsername(): void
    {
        Config::set('database.default', 'mysql');
        Config::set('database.connections.mysql.username', 'root');
        Config::set('database.connections.mysql.password', 'securepassword123456');
        Config::set('database.connections.mysql.host', 'localhost');
        Config::set('app.env', 'production');

        $service = new DatabaseSecurityAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);

        $usernameFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'default database username');
        });

        $this->assertCount(1, $usernameFindings);

        $finding = reset($usernameFindings);
        $this->assertEquals('medium', $finding->severity->value);
    }

    public function testRunPassesWithSecureConfiguration(): void
    {
        Config::set('database.default', 'mysql');
        Config::set('database.connections.mysql.username', 'customuser');
        Config::set('database.connections.mysql.password', 'securepassword123456');
        Config::set('database.connections.mysql.host', 'localhost');
        Config::set('app.env', 'production');

        $service = new DatabaseSecurityAuditService();
        $result = $service->run();

        $this->assertTrue($result);

        $findings = $service->getFindings();

        // May have SSL finding but not password/username findings
        $passwordFindings = array_filter($findings, function ($finding) {
            return str_contains($finding->title, 'password') || str_contains($finding->title, 'username');
        });

        $this->assertEmpty($passwordFindings);
    }
}
