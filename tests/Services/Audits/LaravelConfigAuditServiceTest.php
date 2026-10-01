<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Dgtlss\Warden\Services\Audits\LaravelConfigAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Illuminate\Filesystem\Filesystem;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Process\Process;

final class LaravelConfigAuditServiceTest extends TestCase
{
    private string $originalBasePath;

    private string $temporaryBasePath;

    private string $originalEnvironmentPath;

    private string $originalEnvironmentFile;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalBasePath = $this->app->basePath();
        $this->originalEnvironmentPath = $this->app->environmentPath();
        $this->originalEnvironmentFile = $this->app->environmentFile();
        $this->temporaryBasePath = sys_get_temp_dir() . '/warden-config-' . bin2hex(random_bytes(8));
        mkdir($this->temporaryBasePath, 0777, true);
        $this->app->setBasePath($this->temporaryBasePath);
        $this->app->useEnvironmentPath($this->temporaryBasePath);
        $this->app->loadEnvironmentFrom('.env');
    }

    protected function tearDown(): void
    {
        $this->app->setBasePath($this->originalBasePath);
        $this->app->useEnvironmentPath($this->originalEnvironmentPath);
        $this->app->loadEnvironmentFrom($this->originalEnvironmentFile);
        (new Filesystem())->deleteDirectory($this->temporaryBasePath);
        parent::tearDown();
    }

    #[DataProvider('environmentPathProvider')]
    public function testTrackedConfiguredEnvironmentFileIsReported(string $directory, string $filename): void
    {
        $environmentPath = base_path($directory);
        if (!is_dir($environmentPath)) {
            mkdir($environmentPath, 0700, true);
        }

        $this->app->useEnvironmentPath($environmentPath);
        $this->app->loadEnvironmentFrom($filename);
        file_put_contents($this->app->environmentFilePath(), 'APP_NAME=Warden');
        (new Process(['git', 'init', '--quiet'], base_path()))->mustRun();
        $path = ($directory === '' ? '' : $directory . '/') . $filename;
        (new Process(['git', 'add', '--force', '--', $path], base_path()))->mustRun();

        $auditResult = (new LaravelConfigAuditService())->run(new AuditContext(profile: 'ci'));

        self::assertCount(1, $auditResult->findings);
        self::assertSame('laravel.env.tracked', $auditResult->findings[0]->id);
        self::assertSame($path, $auditResult->findings[0]->path);
        self::assertTrue($auditResult->findings[0]->blocking);
    }

    /** @return iterable<string, array{string, string}> */
    public static function environmentPathProvider(): iterable
    {
        yield 'default environment file' => ['', '.env'];
        yield 'custom filename' => ['', '.env.production'];
        yield 'custom directory and filename' => ['private', '.env.production'];
    }

    public function testExternalEnvironmentFileDoesNotAuditUnusedTrackedDotEnv(): void
    {
        mkdir(base_path('application'), 0700, true);
        $this->app->setBasePath($this->temporaryBasePath . '/application');
        file_put_contents(base_path('.env'), 'APP_NAME=Unused');
        (new Process(['git', 'init', '--quiet'], base_path()))->mustRun();
        (new Process(['git', 'add', '--force', '.env'], base_path()))->mustRun();
        $this->app->useEnvironmentPath($this->temporaryBasePath);
        $this->app->loadEnvironmentFrom('.env.production');
        file_put_contents($this->app->environmentFilePath(), 'APP_NAME=Warden');

        self::assertSame([], (new LaravelConfigAuditService())->run(new AuditContext(profile: 'ci'))->findings);
    }

    public function testTrackedExternalEnvironmentFileInsideParentRepositoryIsReported(): void
    {
        (new Process(['git', 'init', '--quiet'], base_path()))->mustRun();
        $this->app->loadEnvironmentFrom('.env.production');
        file_put_contents($this->app->environmentFilePath(), 'APP_NAME=Warden');
        (new Process(['git', 'add', '--force', '.env.production'], base_path()))->mustRun();
        mkdir(base_path('application'), 0700, true);
        $this->app->setBasePath($this->temporaryBasePath . '/application');

        $auditResult = (new LaravelConfigAuditService())->run(new AuditContext(profile: 'ci'));

        self::assertCount(1, $auditResult->findings);
        self::assertSame('laravel.env.tracked', $auditResult->findings[0]->id);
        self::assertSame($this->app->environmentFilePath(), $auditResult->findings[0]->path);
    }

    public function testEnvironmentFilenameIsALiteralGitPathspec(): void
    {
        $this->app->loadEnvironmentFrom('.env[production]');
        file_put_contents($this->app->environmentFilePath(), 'APP_NAME=Warden');
        file_put_contents(base_path('.envp'), 'APP_NAME=Unused');
        (new Process(['git', 'init', '--quiet'], base_path()))->mustRun();
        (new Process(['git', 'add', '--force', '.envp'], base_path()))->mustRun();

        self::assertSame([], (new LaravelConfigAuditService())->run(new AuditContext(profile: 'ci'))->findings);
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
