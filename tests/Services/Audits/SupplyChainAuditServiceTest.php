<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services\Audits;

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
}
