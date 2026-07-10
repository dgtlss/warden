<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\Services\Audits\SupplyChainAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Symfony\Component\Process\Process;

final class SupplyChainAuditServiceTest extends TestCase
{
    private string $originalBasePath;

    private string $temporaryBasePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalBasePath = $this->app->basePath();
        $this->temporaryBasePath = sys_get_temp_dir() . '/warden-supply-' . bin2hex(random_bytes(8));
        mkdir($this->temporaryBasePath, 0777, true);
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

    public function testInsecureComposerAndMissingJavascriptLockAreReported(): void
    {
        file_put_contents(base_path('composer.json'), json_encode([
            'config' => ['secure-http' => false, 'allow-plugins' => true],
            'repositories' => [['type' => 'composer', 'url' => 'http://packages.example.com']],
        ], JSON_THROW_ON_ERROR));
        file_put_contents(base_path('composer.lock'), '{}');
        file_put_contents(base_path('package.json'), '{"dependencies":{"example":"^1.0"}}');

        $service = new class extends SupplyChainAuditService {
            protected function createComposerValidationProcess(): Process
            {
                return new Process([PHP_BINARY, '-r', 'exit(0);']);
            }
        };
        $auditResult = $service->run(new AuditContext());
        $ids = array_map(static fn ($finding): string => $finding->id, $auditResult->findings);

        self::assertContains('supply-chain.composer.insecure-http', $ids);
        self::assertContains('supply-chain.composer.plugins.unrestricted', $ids);
        self::assertContains('supply-chain.composer.repository.insecure', $ids);
        self::assertContains('supply-chain.javascript-lock.missing', $ids);
    }

    public function testManifestValidationFailureIsAnAuditError(): void
    {
        file_put_contents(base_path('composer.json'), '{"name":"invalid uppercase/name"}');
        file_put_contents(base_path('composer.lock'), '{}');

        $service = new class extends SupplyChainAuditService {
            protected function createComposerValidationProcess(): Process
            {
                return new Process([PHP_BINARY, '-r', 'fwrite(STDERR, "composer.json schema invalid"); exit(2);']);
            }
        };

        $auditResult = $service->run(new AuditContext());

        self::assertSame('composer_validation_failed', $auditResult->errors[0]->code);
    }

    public function testRecentExecutableProductionPackageBlocksWhileOrdinaryAndDevPackagesAdvise(): void
    {
        file_put_contents(base_path('composer.json'), '{"name":"example/app"}');
        file_put_contents(base_path('composer.lock'), json_encode([
            'packages' => [
                ['name' => 'vendor/runtime', 'version' => '1.0.0', 'time' => '2026-07-09T00:00:00Z'],
                ['name' => 'vendor/plugin', 'version' => '2.0.0', 'time' => '2026-07-09T00:00:00Z', 'type' => 'composer-plugin'],
            ],
            'packages-dev' => [
                ['name' => 'vendor/dev-tool', 'version' => '3.0.0', 'time' => '2026-07-09T00:00:00Z'],
            ],
        ], JSON_THROW_ON_ERROR));

        $service = new class extends SupplyChainAuditService {
            protected function createComposerValidationProcess(): Process
            {
                return new Process([PHP_BINARY, '-r', 'exit(0);']);
            }
        };

        $auditResult = $service->run(new AuditContext(scope: 'production', scannedAt: CarbonImmutable::parse('2026-07-10')));
        $all = $service->run(new AuditContext(scope: 'all', scannedAt: CarbonImmutable::parse('2026-07-10')));

        self::assertCount(2, $auditResult->findings);
        self::assertCount(3, $all->findings);
        self::assertSame('supply-chain.composer.recent-package', $auditResult->findings[0]->id);
        self::assertFalse($auditResult->findings[0]->blocking);
        self::assertSame('supply-chain.composer.recent-executable-package', $auditResult->findings[1]->id);
        self::assertTrue($auditResult->findings[1]->blocking);
    }
}
