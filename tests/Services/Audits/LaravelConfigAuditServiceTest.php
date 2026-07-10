<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Dgtlss\Warden\Services\Audits\LaravelConfigAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;

final class LaravelConfigAuditServiceTest extends TestCase
{
    public function testCiProfileDoesNotRequireAnEnvironmentFileOrProductionConfiguration(): void
    {
        config(['app.debug' => true, 'app.key' => null]);

        $auditResult = (new LaravelConfigAuditService())->run(new AuditContext(profile: 'ci'));

        self::assertSame([], $auditResult->findings);
        self::assertTrue($auditResult->succeeded());
    }

    public function testSecureProductionConfigurationPasses(): void
    {
        config([
            'app.debug' => false,
            'app.key' => 'base64:' . base64_encode(random_bytes(32)),
            'app.cipher' => 'AES-256-CBC',
            'app.url' => 'https://example.com',
            'session.secure' => true,
            'session.http_only' => true,
            'session.same_site' => 'lax',
            'telescope.enabled' => false,
            'cors.allowed_origins' => ['https://example.com'],
            'cors.supports_credentials' => false,
        ]);

        $auditResult = (new LaravelConfigAuditService())->run(new AuditContext(profile: 'production'));

        self::assertSame([], $auditResult->findings);
    }

    public function testInsecureProductionConfigurationProducesHighConfidenceRules(): void
    {
        config([
            'app.debug' => true,
            'app.key' => 'short',
            'app.cipher' => 'AES-256-CBC',
            'app.url' => 'http://example.com',
            'session.secure' => false,
            'session.http_only' => false,
            'session.same_site' => '',
        ]);

        $auditResult = (new LaravelConfigAuditService())->run(new AuditContext(profile: 'production'));
        $ids = array_map(static fn ($finding): string => $finding->id, $auditResult->findings);

        self::assertContains('laravel.debug.enabled', $ids);
        self::assertContains('laravel.app-key.invalid', $ids);
        self::assertContains('laravel.url.insecure', $ids);
        self::assertContains('laravel.session.secure', $ids);
        self::assertContains('laravel.session.http-only', $ids);
        self::assertContains('laravel.session.same-site', $ids);
    }
}
