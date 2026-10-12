<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Dgtlss\Warden\Services\Audits\ComposerAuditService;
use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Symfony\Component\Process\Process;

final class DependencyAuditServiceTest extends TestCase
{
    private string $originalBasePath;

    private string $temporaryBasePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalBasePath = $this->app->basePath();
        $this->temporaryBasePath = sys_get_temp_dir() . '/warden-dependencies-' . bin2hex(random_bytes(8));
        mkdir($this->temporaryBasePath, 0777, true);
        file_put_contents($this->temporaryBasePath . '/composer.lock', '{}');
        $this->app->setBasePath($this->temporaryBasePath);
    }

    protected function tearDown(): void
    {
        $this->app->setBasePath($this->originalBasePath);
        foreach (glob($this->temporaryBasePath . '/*') ?: [] as $path) {
            unlink($path);
        }

        rmdir($this->temporaryBasePath);
        parent::tearDown();
    }

    public function testComposerUsesLockedProductionScopeAndParsesFindings(): void
    {
        $service = new class extends ComposerAuditService {
            /** @var list<string> */
            public array $command = [];

            protected function createProcess(array $command, int $timeout): Process
            {
                $this->command = $command;
                $json = json_encode([
                    'advisories' => ['vendor/package' => [[
                        'advisoryId' => 'GHSA-test',
                        'title' => 'Test advisory',
                        'severity' => 'high',
                        'affectedVersions' => '<2.0',
                        'link' => 'https://example.com/GHSA-test',
                    ]]],
                    'abandoned' => ['old/package' => 'new/package'],
                ], JSON_THROW_ON_ERROR);

                return new Process([PHP_BINARY, '-r', sprintf('echo %s; exit(1);', var_export($json, true))]);
            }
        };

        $auditResult = $service->run(new AuditContext(scope: 'production'));

        self::assertContains('--locked', $service->command);
        self::assertContains('--no-dev', $service->command);
        self::assertCount(2, $auditResult->findings);
        self::assertTrue($auditResult->succeeded());
    }

    public function testMalformedComposerOutputIsAnExecutionError(): void
    {
        $service = new class extends ComposerAuditService {
            protected function createProcess(array $command, int $timeout): Process
            {
                return new Process([PHP_BINARY, '-r', 'echo "not-json"; exit(2);']);
            }
        };

        $auditResult = $service->run(new AuditContext());

        self::assertSame('malformed_output', $auditResult->errors[0]->code);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('npmLockfiles')]
    public function testNpmUsesLockfileOnlyAndProductionDependencyScope(string $lockfile): void
    {
        file_put_contents(base_path($lockfile), '{}');

        $service = new class extends NpmAuditService {
            /** @var list<string> */
            public array $command = [];

            protected function createProcess(array $command, int $timeout): Process
            {
                $this->command = $command;
                return new Process([PHP_BINARY, '-r', 'echo "{\"vulnerabilities\":[]}";']);
            }
        };
        $auditResult = $service->run(new AuditContext(scope: 'production'));

        self::assertContains('--package-lock-only', $service->command);
        self::assertContains('--omit=dev', $service->command);
        self::assertTrue($auditResult->succeeded());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('advisoryLockfiles')]
    public function testNpmAdvisoriesUseTheSelectedLockfileInReports(array $lockfiles, string $expected): void
    {
        foreach ($lockfiles as $lockfile) {
            file_put_contents(base_path($lockfile), '{}');
        }

        $service = new class extends NpmAuditService {
            protected function createProcess(array $command, int $timeout): Process
            {
                $json = json_encode(['vulnerabilities' => ['example' => [
                    'severity' => 'high', 'range' => '<2',
                    'via' => [['title' => 'Test advisory', 'source' => 42]],
                ]]], JSON_THROW_ON_ERROR);
                return new Process([PHP_BINARY, '-r', 'echo ' . var_export($json, true) . '; exit(1);']);
            }
        };
        $auditResult = $service->run(new AuditContext());
        self::assertSame([], $auditResult->errors);
        self::assertCount(1, $auditResult->findings);
        self::assertSame($expected, $auditResult->findings[0]->path);
        $auditReport = new \Dgtlss\Warden\ValueObjects\AuditReport(new AuditContext(), [$auditResult]);
        $gitlab = json_decode((new \Dgtlss\Warden\Reporters\GitLabReporter())->format($auditReport), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($expected, $gitlab['vulnerabilities'][0]['location']['file']);
        self::assertSame($expected, $gitlab['dependency_files'][0]['path']);
        self::assertSame('npm', $gitlab['dependency_files'][0]['package_manager']);
        $json = json_decode((new \Dgtlss\Warden\Reporters\JsonReporter())->format($auditReport), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($expected, $json['findings'][0]['location']['path']);
    }

    /** @return iterable<string, array{list<string>, string}> */
    public static function advisoryLockfiles(): iterable
    {
        yield 'package lock' => [['package-lock.json'], 'package-lock.json'];
        yield 'shrinkwrap' => [['npm-shrinkwrap.json'], 'npm-shrinkwrap.json'];
        yield 'shrinkwrap takes precedence' => [['package-lock.json', 'npm-shrinkwrap.json'], 'npm-shrinkwrap.json'];
    }

    /** @return iterable<string, array{string}> */
    public static function npmLockfiles(): iterable
    {
        yield 'package lock' => ['package-lock.json'];
        yield 'shrinkwrap' => ['npm-shrinkwrap.json'];
    }

}
