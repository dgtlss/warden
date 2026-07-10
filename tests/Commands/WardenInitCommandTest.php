<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class WardenInitCommandTest extends TestCase
{
    private string $originalBasePath;

    private string $temporaryBasePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalBasePath = $this->app->basePath();
        $this->temporaryBasePath = sys_get_temp_dir() . '/warden-init-' . bin2hex(random_bytes(8));
        mkdir($this->temporaryBasePath, 0777, true);
        $this->app->setBasePath($this->temporaryBasePath);
    }

    protected function tearDown(): void
    {
        $this->app->setBasePath($this->originalBasePath);
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->temporaryBasePath, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) {
            if ($item instanceof SplFileInfo) {
                $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
            }
        }

        rmdir($this->temporaryBasePath);
        parent::tearDown();
    }

    public function testGithubInitializationIsPinnedAndNonDestructive(): void
    {
        self::assertSame(0, Artisan::call('warden:init', ['--ci' => 'github']));

        $workflow = file_get_contents(base_path('.github/workflows/warden.yml'));
        self::assertIsString($workflow);
        self::assertMatchesRegularExpression('/actions\/checkout@[a-f0-9]{40}/', $workflow);
        self::assertMatchesRegularExpression('/setup-php@[a-f0-9]{40}/', $workflow);
        self::assertStringContainsString("php-version: '" . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . "'", $workflow);
        self::assertFileExists(config_path('warden.php'));

        file_put_contents(config_path('warden.php'), '<?php return ["sentinel" => true];');
        self::assertSame(1, Artisan::call('warden:init', ['--ci' => 'github']));
        self::assertSame(0, Artisan::call('warden:init', ['--ci' => 'github', '--force' => true]));
        self::assertStringContainsString('sentinel', (string) file_get_contents(config_path('warden.php')));
    }

    public function testGitlabInitializationPreservesAnExistingRootPipeline(): void
    {
        file_put_contents(base_path('.gitlab-ci.yml'), "existing: true\n");

        self::assertSame(0, Artisan::call('warden:init', ['--ci' => 'gitlab']));

        self::assertSame("existing: true\n", file_get_contents(base_path('.gitlab-ci.yml')));
        self::assertFileExists(base_path('.gitlab/warden.yml'));
        self::assertStringContainsString('dependency_scanning', (string) file_get_contents(base_path('.gitlab/warden.yml')));
    }
}
