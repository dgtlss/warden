<?php

namespace Dgtlss\Warden\Tests\Services\Audits;

use Dgtlss\Warden\Providers\WardenServiceProvider;
use Dgtlss\Warden\Services\Audits\DebugModeAuditService;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class DebugModeAuditServiceTest extends TestCase
{
    private array $originalCiEnvironmentValues = [];

    private ?string $temporaryBasePath = null;

    private ?string $originalBasePath = null;

    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->originalBasePath = $this->app->basePath();
        $this->unsetCiEnvironmentFlags();

        config([
            'app.env' => 'production',
            'app.debug' => false,
            'horizon.enabled' => false,
            'telescope.enabled' => false,
        ]);
    }

    protected function tearDown(): void
    {
        if ($this->originalBasePath !== null) {
            $this->app->setBasePath($this->originalBasePath);
        }

        $this->deleteTemporaryBasePath();
        $this->restoreCiEnvironmentFlags();

        parent::tearDown();
    }

    public function testHorizonIsNotFlaggedAsADevelopmentPackageInProduction(): void
    {
        $this->setInstalledPackages([
            ['name' => 'laravel/horizon'],
        ]);

        $service = app(DebugModeAuditService::class);
        $service->run();

        $this->assertFalse($this->findingExists(
            $service->getFindings(),
            'Development package detected in production',
            'laravel/horizon'
        ));
    }

    public function testHorizonRoutesAreNotFlaggedAsTestingRoutes(): void
    {
        $this->setInstalledPackages([]);
        Route::get('horizon/dashboard', static fn () => 'ok');

        $service = app(DebugModeAuditService::class);
        $service->run();

        $this->assertFalse($this->findingExists(
            $service->getFindings(),
            'Testing routes are exposed',
            'routes'
        ));
    }

    public function testTelescopeRoutesAreStillFlaggedAsTestingRoutes(): void
    {
        $this->setInstalledPackages([]);
        Route::get('telescope/dashboard', static fn () => 'ok');

        $service = app(DebugModeAuditService::class);
        $service->run();

        $this->assertTrue($this->findingExists(
            $service->getFindings(),
            'Testing routes are exposed',
            'routes'
        ));
    }

    public function testDuskRoutesAreStillFlaggedAsTestingRoutes(): void
    {
        $this->setInstalledPackages([]);
        Route::get('_dusk/ping', static fn () => 'ok');

        $service = app(DebugModeAuditService::class);
        $service->run();

        $this->assertTrue($this->findingExists(
            $service->getFindings(),
            'Testing routes are exposed',
            'routes'
        ));
    }

    /**
     * @param array<int, array<string, mixed>> $packages
     */
    private function setInstalledPackages(array $packages): void
    {
        $this->deleteTemporaryBasePath();

        $this->temporaryBasePath = sys_get_temp_dir() . '/warden-debug-mode-' . bin2hex(random_bytes(8));
        $installedPath = $this->temporaryBasePath . '/vendor/composer';

        mkdir($installedPath, 0777, true);
        file_put_contents(
            $installedPath . '/installed.json',
            json_encode(['packages' => $packages], JSON_THROW_ON_ERROR)
        );

        $this->app->setBasePath($this->temporaryBasePath);
    }

    /**
     * @param array<array<string, mixed>> $findings
     */
    private function findingExists(array $findings, string $title, string $package): bool
    {
        foreach ($findings as $finding) {
            if (($finding['title'] ?? null) === $title && ($finding['package'] ?? null) === $package) {
                return true;
            }
        }

        return false;
    }

    private function unsetCiEnvironmentFlags(): void
    {
        foreach ($this->ciEnvironmentFlags() as $flag) {
            $this->originalCiEnvironmentValues[$flag] = getenv($flag);
            putenv($flag);
        }
    }

    private function restoreCiEnvironmentFlags(): void
    {
        foreach ($this->originalCiEnvironmentValues as $flag => $value) {
            if ($value === false) {
                putenv($flag);
                continue;
            }

            putenv($flag . '=' . $value);
        }
    }

    /**
     * @return array<int, string>
     */
    private function ciEnvironmentFlags(): array
    {
        return [
            'CI',
            'CONTINUOUS_INTEGRATION',
            'GITHUB_ACTIONS',
            'GITLAB_CI',
            'JENKINS_URL',
            'TRAVIS',
            'CIRCLECI',
        ];
    }

    private function deleteTemporaryBasePath(): void
    {
        if ($this->temporaryBasePath === null || !is_dir($this->temporaryBasePath)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->temporaryBasePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
                continue;
            }

            unlink($item->getPathname());
        }

        rmdir($this->temporaryBasePath);
        $this->temporaryBasePath = null;
    }
}
