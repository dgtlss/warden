<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Dgtlss\Warden\Contracts\AuditService;
use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\Contracts\WardenPlugin;
use Dgtlss\Warden\Exceptions\ConfigurationException;
use Dgtlss\Warden\Plugins\AbstractPlugin;
use Dgtlss\Warden\Services\PluginManager;
use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Mockery;

class PluginManagerTest extends TestCase
{
    private PluginManager $manager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->manager = new PluginManager($this->app);
    }

    public function testRegisterPluginSuccessfully(): void
    {
        $plugin = new TestPlugin();

        $this->manager->register($plugin);

        $this->assertTrue($this->manager->isRegistered('test-plugin'));
        $this->assertSame($plugin, $this->manager->get('test-plugin'));
    }

    public function testRegisterPluginByClass(): void
    {
        $this->manager->registerClass(TestPlugin::class);

        $this->assertTrue($this->manager->isRegistered('test-plugin'));
    }

    public function testRegisterDuplicatePluginThrowsException(): void
    {
        $plugin1 = new TestPlugin();
        $plugin2 = new TestPlugin();

        $this->manager->register($plugin1);

        $this->expectException(ConfigurationException::class);
        $this->manager->register($plugin2);
    }

    public function testRegisterNonExistentClassThrowsException(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->manager->registerClass('NonExistent\\Plugin\\Class');
    }

    public function testGetAuditsIncludesPluginAudits(): void
    {
        $plugin = new TestPluginWithAudit();

        $this->manager->register($plugin);

        $audits = $this->manager->getAudits();

        $this->assertContains(TestAuditService::class, $audits);
    }

    public function testGetChannelsIncludesPluginChannels(): void
    {
        $plugin = new TestPluginWithChannel();

        $this->manager->register($plugin);

        $channels = $this->manager->getChannels();

        $this->assertContains(TestNotificationChannel::class, $channels);
    }

    public function testGetCommandsIncludesPluginCommands(): void
    {
        $plugin = new TestPluginWithCommand();

        $this->manager->register($plugin);

        $commands = $this->manager->getCommands();

        $this->assertContains(TestCommand::class, $commands);
    }

    public function testPluginBootIsCalled(): void
    {
        $bootCalled = false;

        $plugin = Mockery::mock(WardenPlugin::class);
        $plugin->shouldReceive('name')->andReturn('mock-plugin');
        $plugin->shouldReceive('register')->once();
        $plugin->shouldReceive('boot')->once()->andReturnUsing(function () use (&$bootCalled) {
            $bootCalled = true;
        });

        $this->manager->register($plugin);
        $this->manager->boot();

        $this->assertTrue($bootCalled);
    }

    public function testBootOnlyCalledOnce(): void
    {
        $bootCount = 0;

        $plugin = Mockery::mock(WardenPlugin::class);
        $plugin->shouldReceive('name')->andReturn('mock-plugin');
        $plugin->shouldReceive('register')->once();
        $plugin->shouldReceive('boot')->andReturnUsing(function () use (&$bootCount) {
            $bootCount++;
        });

        $this->manager->register($plugin);
        $this->manager->boot();
        $this->manager->boot(); // Second call should not trigger boot again

        $this->assertEquals(1, $bootCount);
    }

    public function testGetReturnsNullForUnregisteredPlugin(): void
    {
        $this->assertNull($this->manager->get('non-existent'));
    }

    public function testAllReturnsAllRegisteredPlugins(): void
    {
        $plugin1 = new TestPlugin();
        $plugin2 = new AnotherTestPlugin();

        $this->manager->register($plugin1);
        $this->manager->register($plugin2);

        $all = $this->manager->all();

        $this->assertCount(2, $all);
        $this->assertArrayHasKey('test-plugin', $all);
        $this->assertArrayHasKey('another-test-plugin', $all);
    }

    public function testCountReturnsCorrectNumber(): void
    {
        $this->assertEquals(0, $this->manager->count());

        $this->manager->register(new TestPlugin());
        $this->assertEquals(1, $this->manager->count());

        $this->manager->register(new AnotherTestPlugin());
        $this->assertEquals(2, $this->manager->count());
    }

    public function testGetMetadataReturnsPluginInfo(): void
    {
        $plugin = new TestPlugin();
        $this->manager->register($plugin);

        $metadata = $this->manager->getMetadata();

        $this->assertArrayHasKey('test-plugin', $metadata);
        $this->assertEquals('test-plugin', $metadata['test-plugin']['name']);
        $this->assertEquals('1.0.0', $metadata['test-plugin']['version']);
    }

    public function testRegisterFromConfigLoadsPlugins(): void
    {
        Config::set('warden.plugins.registered', [
            TestPlugin::class,
        ]);

        $this->manager->registerFromConfig();

        $this->assertTrue($this->manager->isRegistered('test-plugin'));
    }

    public function testRegisterFromConfigIgnoresInvalidClasses(): void
    {
        Config::set('warden.plugins.registered', [
            'InvalidClass',
            TestPlugin::class,
        ]);

        $this->manager->registerFromConfig();

        $this->assertTrue($this->manager->isRegistered('test-plugin'));
        $this->assertEquals(1, $this->manager->count());
    }

    public function testAutoDiscoverDisabledByConfig(): void
    {
        Config::set('warden.plugins.auto_discover', false);

        // Create a new manager instance with the updated config
        $manager = new PluginManager($this->app);

        // Calling discover should do nothing when disabled
        $manager->discover();

        $this->assertEquals(0, $manager->count());
    }

    public function testDiscoverSkipsPackagesWithoutWardenConfig(): void
    {
        $installedJson = json_encode([
            'packages' => [
                [
                    'name' => 'some/package',
                    'version' => '1.0.0',
                ],
            ],
        ]);

        $installedPath = base_path('vendor/composer/installed.json');
        $originalContent = File::exists($installedPath) ? File::get($installedPath) : null;

        File::ensureDirectoryExists(dirname($installedPath));
        File::put($installedPath, $installedJson);

        try {
            $manager = new PluginManager($this->app);
            $manager->discover();

            $this->assertEquals(0, $manager->count());
        } finally {
            if ($originalContent !== null) {
                File::put($installedPath, $originalContent);
            } elseif (File::exists($installedPath)) {
                File::delete($installedPath);
            }
        }
    }

    public function testAuditsDeduplicateAcrossPlugins(): void
    {
        $plugin1 = new TestPluginWithAudit();
        $plugin2 = new TestPluginWithSameAudit();

        $this->manager->register($plugin1);
        $this->manager->register($plugin2);

        $audits = $this->manager->getAudits();

        // Should only contain TestAuditService once
        $this->assertEquals(1, count(array_filter($audits, fn($a) => $a === TestAuditService::class)));
    }
}

// Test fixtures

class TestPlugin extends AbstractPlugin
{
    protected string $name = 'test-plugin';
    protected string $version = '1.0.0';
    protected string $description = 'A test plugin';
}

class AnotherTestPlugin extends AbstractPlugin
{
    protected string $name = 'another-test-plugin';
    protected string $version = '2.0.0';
    protected string $description = 'Another test plugin';
}

class TestPluginWithAudit extends AbstractPlugin
{
    protected string $name = 'audit-plugin';

    public function audits(): array
    {
        return [TestAuditService::class];
    }
}

class TestPluginWithSameAudit extends AbstractPlugin
{
    protected string $name = 'audit-plugin-2';

    public function audits(): array
    {
        return [TestAuditService::class];
    }
}

class TestPluginWithChannel extends AbstractPlugin
{
    protected string $name = 'channel-plugin';

    public function channels(): array
    {
        return [TestNotificationChannel::class];
    }
}

class TestPluginWithCommand extends AbstractPlugin
{
    protected string $name = 'command-plugin';

    public function commands(): array
    {
        return [TestCommand::class];
    }
}

class TestAuditService implements AuditService
{
    public function run(): bool
    {
        return true;
    }

    public function getName(): string
    {
        return 'test-audit';
    }

    public function getFindings(): array
    {
        return [];
    }
}

class TestNotificationChannel implements NotificationChannel
{
    public function send(array $findings): void
    {
    }

    public function sendAbandonedPackages(array $abandonedPackages): void
    {
    }

    public function isConfigured(): bool
    {
        return true;
    }

    public function getName(): string
    {
        return 'test-channel';
    }
}

class TestCommand extends \Illuminate\Console\Command
{
    protected $signature = 'test:command';

    public function handle(): void
    {
    }
}
