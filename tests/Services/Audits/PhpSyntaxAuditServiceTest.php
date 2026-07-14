<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Dgtlss\Warden\Services\Audits\PhpSyntaxAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Symfony\Component\Process\Process;

final class PhpSyntaxAuditServiceTest extends TestCase
{
    private string $originalBasePath;

    private string $temporaryBasePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalBasePath = $this->app->basePath();
        $this->temporaryBasePath = sys_get_temp_dir() . '/warden-syntax-' . bin2hex(random_bytes(8));
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

    public function testTimeoutRetainsEarlierSyntaxFindingsAndReturnsAnAuditError(): void
    {
        $this->write('app/A-Broken.php', '<?php function broken( {');
        $this->write('app/B-Slow.php', '<?php return true;');
        $service = new class extends PhpSyntaxAuditService {
            private int $processes = 0;

            protected function createProcess(string $path, float $timeout): Process
            {
                $this->processes++;
                if ($this->processes === 1) {
                    return parent::createProcess($path, $timeout);
                }

                return new Process([PHP_BINARY, '-r', 'usleep(50000);'], base_path(), null, null, 0.001);
            }
        };

        $auditResult = $service->run(new AuditContext(timeout: 1));

        self::assertCount(1, $auditResult->findings);
        self::assertSame('quality.php.syntax', $auditResult->findings[0]->id);
        self::assertSame('timeout', $auditResult->errors[0]->code);
        self::assertFalse($auditResult->succeeded());
    }

    public function testExclusionsAcceptEitherPathSeparator(): void
    {
        config(['warden.audits.php_syntax.exclude' => ['bootstrap\\cache']]);
        $this->write('bootstrap/cache/Broken.php', '<?php function broken( {');

        $auditResult = (new PhpSyntaxAuditService())->run(new AuditContext());

        self::assertSame([], $auditResult->findings);
        self::assertSame([], $auditResult->errors);
    }

    public function testEachProcessReceivesOnlyTheRemainingAuditBudget(): void
    {
        $this->write('app/A.php', '<?php return true;');
        $this->write('app/B.php', '<?php return true;');
        $service = new class extends PhpSyntaxAuditService {
            /** @var list<float> */
            public array $timeouts = [];

            protected function createProcess(string $path, float $timeout): Process
            {
                $this->timeouts[] = $timeout;

                return new Process([PHP_BINARY, '-r', 'usleep(20000);'], base_path(), null, null, $timeout);
            }
        };

        $auditResult = $service->run(new AuditContext(timeout: 1));

        self::assertSame([], $auditResult->errors);
        self::assertCount(2, $service->timeouts);
        self::assertLessThan($service->timeouts[0], $service->timeouts[1]);
    }

    private function write(string $relative, string $contents): void
    {
        $path = $this->temporaryBasePath . '/' . $relative;
        if (!is_dir(dirname($path))) {
            mkdir(dirname($path), 0777, true);
        }

        file_put_contents($path, $contents);
    }
}
