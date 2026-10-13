<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Commands;

use Dgtlss\Warden\Commands\WardenInitCommand;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionMethod;
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

    public function testGitlabLockfileBootstrapRunsWithBothNpmLockfileNames(): void
    {
        self::assertSame(0, Artisan::call('warden:init', ['--ci' => 'gitlab']));
        $pipeline = \Symfony\Component\Yaml\Yaml::parseFile(base_path('.gitlab/warden.yml'));
        self::assertArrayNotHasKey('stages', $pipeline);
        self::assertSame('.pre', $pipeline['warden']['stage']);
        $root = \Symfony\Component\Yaml\Yaml::parseFile(base_path('.gitlab-ci.yml'));
        self::assertSame('test', $root['warden']['stage']);
        mkdir(base_path('bin'));
        file_put_contents(base_path('bin/apk'), "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> apk.log\n");
        chmod(base_path('bin/apk'), 0755);
        foreach ([null, 'package-lock.json', 'npm-shrinkwrap.json'] as $lockfile) {
            if ($lockfile !== null) { file_put_contents(base_path($lockfile), '{}'); }

            $process = new \Symfony\Component\Process\Process(['sh', '-ec', implode("\n", $pipeline['warden']['before_script'])], base_path(), ['PATH' => base_path('bin') . ':' . getenv('PATH')]);
            $process->mustRun();
            if ($lockfile === null) {
                self::assertFileDoesNotExist(base_path('apk.log'));
            } else {
                self::assertStringContainsString('add --no-cache nodejs npm', file_get_contents(base_path('apk.log')));
                unlink(base_path($lockfile));
                unlink(base_path('apk.log'));
            }
        }

        self::assertSame('always', $pipeline['warden']['artifacts']['when']);
        self::assertSame(1, substr_count(implode("\n", $pipeline['warden']['script']), 'warden:audit'));
        self::assertStringContainsString('--report=json-v2.1:warden.json', implode("\n", $pipeline['warden']['script']));
        self::assertStringContainsString('--report=junit:', implode("\n", $pipeline['warden']['script']));
    }

    public function testGithubSummaryExecutesWithMissingAndIncompleteReports(): void
    {
        self::assertSame(0, Artisan::call('warden:init', ['--ci' => 'github']));
        $workflow = \Symfony\Component\Yaml\Yaml::parseFile(base_path('.github/workflows/warden.yml'));
        $steps = array_column($workflow['jobs']['warden']['steps'], null, 'name');
        self::assertStringContainsString('--report=json-v2.1:warden.json', $steps['Run Warden']['run']);
        self::assertStringContainsString('--report=sarif:', $steps['Run Warden']['run']);
        self::assertSame('always()', $steps['Retain Warden reports']['if']);
        self::assertTrue($steps['Upload SARIF to code scanning (opt-in)']['continue-on-error']);
        self::assertArrayNotHasKey('security-events', $workflow['permissions']);
        $script = $steps['Warden summary']['run'];
        $summary = base_path('summary.md');
        $process = new \Symfony\Component\Process\Process(['sh', '-ec', $script], base_path(), ['GITHUB_STEP_SUMMARY' => $summary]);
        $process->mustRun();
        self::assertStringContainsString('report unavailable', file_get_contents($summary));
        unlink($summary);
        file_put_contents(base_path('warden.json'), json_encode([
            'run' => ['status' => 'failed'], 'gate' => ['exit_code' => 2],
            'summary' => ['blocking' => 0, 'advisory' => 1, 'errors' => 1],
        ], JSON_THROW_ON_ERROR));
        $process->mustRun();
        self::assertStringContainsString('gate exit: 2', file_get_contents($summary));
        self::assertStringContainsString('0 blocking, 1 advisory, 1 errors', file_get_contents($summary));
        unlink($summary);
        file_put_contents(base_path('warden.json'), json_encode([
            'run' => ['status' => 'completed'],
            'summary' => ['blocking' => 1, 'advisory' => 0, 'errors' => 0],
        ], JSON_THROW_ON_ERROR));
        $process->mustRun();
        self::assertSame('', $process->getErrorOutput());
        self::assertStringContainsString('gate exit: unavailable (legacy report)', file_get_contents($summary));
        self::assertStringContainsString('1 blocking, 0 advisory, 0 errors', file_get_contents($summary));
    }

    public function testMissingBundledStubDoesNotProduceEmptyContents(): void
    {
        $reflectionMethod = new ReflectionMethod(WardenInitCommand::class, 'stub');

        self::assertNull($reflectionMethod->invoke($this->app->make(WardenInitCommand::class), 'missing.yml'));
        self::assertFileDoesNotExist(base_path('.github/workflows/warden.yml'));
    }
}
