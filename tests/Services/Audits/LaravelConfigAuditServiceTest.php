<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Dgtlss\Warden\Services\Audits\LaravelConfigAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;

final class LaravelConfigAuditServiceTest extends TestCase
{
    private string $originalBasePath;

    private string $temporaryBasePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalBasePath = $this->app->basePath();
        $this->temporaryBasePath = sys_get_temp_dir() . '/warden-config-' . bin2hex(random_bytes(8));
        mkdir($this->temporaryBasePath, 0777, true);
        $this->app->setBasePath($this->temporaryBasePath);
    }

    protected function tearDown(): void
    {
        $this->app->setBasePath($this->originalBasePath);
        rmdir($this->temporaryBasePath);
        parent::tearDown();
    }

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

    public function testDebugToolsHaveDistinctStableRuleIds(): void
    {
        foreach ([
            'Laravel\\Telescope\\Telescope',
            'Barryvdh\\Debugbar\\LaravelDebugbar',
            'Clockwork\\Clockwork',
        ] as $class) {
            if (!class_exists($class)) {
                class_alias(DebugToolFixture::class, $class);
            }
        }

        config([
            'app.debug' => false,
            'app.key' => 'base64:' . base64_encode(random_bytes(32)),
            'app.cipher' => 'AES-256-CBC',
            'app.url' => 'https://example.com',
            'session.secure' => true,
            'session.http_only' => true,
            'session.same_site' => 'lax',
            'cors.allowed_origins' => ['https://example.com'],
            'cors.supports_credentials' => false,
            'telescope.enabled' => true,
            'debugbar.enabled' => true,
            'clockwork.enable' => true,
        ]);

        $auditResult = (new LaravelConfigAuditService())->run(new AuditContext(profile: 'production'));

        self::assertSame([
            'laravel.debug-tool.telescope-enabled',
            'laravel.debug-tool.debugbar-enabled',
            'laravel.debug-tool.clockwork-enabled',
        ], array_map(static fn ($finding): string => $finding->id, $auditResult->findings));
    }
}

final class DebugToolFixture
{
}
