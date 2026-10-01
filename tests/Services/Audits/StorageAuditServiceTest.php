<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Dgtlss\Warden\Services\Audits\StorageAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Illuminate\Filesystem\Filesystem;

final class StorageAuditServiceTest extends TestCase
{
    private string $temporaryRoot;

    /** @var array<string, string> */
    private array $originalPaths;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalPaths = [
            'base' => $this->app->basePath(),
            'storage' => $this->app->storagePath(),
            'bootstrap' => $this->app->bootstrapPath(),
            'environment' => $this->app->environmentPath(),
            'file' => $this->app->environmentFile(),
        ];
        $this->temporaryRoot = sys_get_temp_dir() . '/warden-storage-' . bin2hex(random_bytes(8));
        $this->app->setBasePath($this->temporaryRoot . '/app');
        $this->app->useStoragePath(base_path('storage'));
        $this->app->useBootstrapPath(base_path('bootstrap'));
        $this->app->useEnvironmentPath(base_path());
        $this->app->loadEnvironmentFrom('.env');
        foreach (['storage/framework', 'storage/logs', 'bootstrap/cache'] as $directory) {
            mkdir(base_path($directory), 0700, true);
        }

        file_put_contents(base_path('.env'), 'APP_NAME=Warden');
        chmod(base_path('.env'), 0600);
    }

    protected function tearDown(): void
    {
        $this->app->setBasePath($this->originalPaths['base']);
        $this->app->useStoragePath($this->originalPaths['storage']);
        $this->app->useBootstrapPath($this->originalPaths['bootstrap']);
        $this->app->useEnvironmentPath($this->originalPaths['environment']);
        $this->app->loadEnvironmentFrom($this->originalPaths['file']);
        (new Filesystem())->deleteDirectory($this->temporaryRoot);
        parent::tearDown();
    }

    public function testSecureDefaultPathsPass(): void
    {
        self::assertSame([], (new StorageAuditService())->run(new AuditContext(profile: 'production'))->findings);
    }

    public function testCustomStorageAndBootstrapPathsReplaceDefaultDirectories(): void
    {
        foreach (['storage/framework', 'storage/logs', 'bootstrap/cache'] as $directory) {
            chmod(base_path($directory), 0777);
        }

        $this->app->useStoragePath(base_path('../runtime'));
        $this->app->useBootstrapPath($this->temporaryRoot . '/bootstrap');
        mkdir(storage_path('framework'), 0700, true);
        mkdir(storage_path('logs'), 0700, true);
        mkdir($this->app->bootstrapPath('cache'), 0700, true);

        self::assertSame([], (new StorageAuditService())->run(new AuditContext(profile: 'production'))->findings);
    }

    public function testWorldWritableCustomStorageIsReportedAtItsActualPath(): void
    {
        $this->app->useStoragePath($this->temporaryRoot . '/runtime');
        mkdir(storage_path('framework'), 0700, true);
        mkdir(storage_path('logs'), 0700, true);
        chmod(storage_path('logs'), 0777);

        $auditResult = (new StorageAuditService())->run(new AuditContext(profile: 'production'));

        self::assertCount(1, $auditResult->findings);
        self::assertSame('deployment.path.world-writable', $auditResult->findings[0]->id);
        self::assertSame(storage_path('logs'), $auditResult->findings[0]->path);
        self::assertFalse($auditResult->findings[0]->blocking);
    }

    public function testMissingCustomStorageDirectoryIsStillReported(): void
    {
        $this->app->useStoragePath($this->temporaryRoot . '/runtime');
        mkdir(storage_path('logs'), 0700, true);

        $auditResult = (new StorageAuditService())->run(new AuditContext(profile: 'production'));

        self::assertCount(1, $auditResult->findings);
        self::assertSame('deployment.storage.not-writable', $auditResult->findings[0]->id);
        self::assertSame(storage_path('framework'), $auditResult->findings[0]->path);
    }

    public function testCustomEnvironmentDirectoryAndFilenameAreAudited(): void
    {
        $this->app->useEnvironmentPath($this->temporaryRoot . '/private');
        $this->app->loadEnvironmentFrom('.env.production');
        mkdir($this->app->environmentPath(), 0700, true);
        file_put_contents($this->app->environmentFilePath(), 'APP_NAME=Warden');
        chmod($this->app->environmentFilePath(), 0644);

        $auditResult = (new StorageAuditService())->run(new AuditContext(profile: 'production'));

        self::assertCount(1, $auditResult->findings);
        self::assertSame('deployment.env.permissions', $auditResult->findings[0]->id);
        self::assertSame($this->app->environmentFilePath(), $auditResult->findings[0]->path);
    }

    public function testUnusedDefaultEnvironmentFileIsNotAudited(): void
    {
        chmod(base_path('.env'), 0644);
        $this->app->loadEnvironmentFrom('.env.production');
        file_put_contents($this->app->environmentFilePath(), 'APP_NAME=Warden');
        chmod($this->app->environmentFilePath(), 0600);

        self::assertSame([], (new StorageAuditService())->run(new AuditContext(profile: 'production'))->findings);
    }

    public function testDefaultFindingPathsRemainRelativeAndCiSkipsPermissions(): void
    {
        chmod(base_path('.env'), 0644);
        chmod(storage_path('logs'), 0777);

        $auditResult = (new StorageAuditService())->run(new AuditContext(profile: 'production'));

        self::assertSame(['.env', 'storage/logs'], array_column($auditResult->findings, 'path'));
        self::assertSame([], (new StorageAuditService())->run(new AuditContext(profile: 'ci'))->findings);
    }
}
