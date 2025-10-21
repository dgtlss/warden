<?php

namespace Dgtlss\Warden\Tests\Services;

use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\Services\PluginManager;
use Dgtlss\Warden\Contracts\AuditPluginInterface;
use Dgtlss\Warden\Abstracts\AbstractAuditPlugin;
use Mockery;

class PluginManagerTest extends TestCase
{
    protected PluginManager $pluginManager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->pluginManager = new PluginManager();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function testCanRegisterPlugin()
    {
        $plugin = $this->createMockPlugin('test-plugin', 'Test Plugin', '1.0.0');

        $this->pluginManager->register($plugin);

        $this->assertTrue($this->pluginManager->hasPlugin('test-plugin'));
        $this->assertSame($plugin, $this->pluginManager->getPlugin('test-plugin'));
        $this->assertTrue($this->pluginManager->isPluginEnabled('test-plugin'));
    }

    public function testCannotRegisterDuplicatePlugin()
    {
        $plugin1 = $this->createMockPlugin('test-plugin', 'Test Plugin 1', '1.0.0');
        $plugin2 = $this->createMockPlugin('test-plugin', 'Test Plugin 2', '2.0.0');

        $this->pluginManager->register($plugin1);
        $this->pluginManager->register($plugin2); // Should not overwrite

        $this->assertSame($plugin1, $this->pluginManager->getPlugin('test-plugin'));
    }

    public function testCanUnregisterPlugin()
    {
        $plugin = $this->createMockPlugin('test-plugin', 'Test Plugin', '1.0.0');

        $this->pluginManager->register($plugin);
        $this->assertTrue($this->pluginManager->hasPlugin('test-plugin'));

        $this->pluginManager->unregister('test-plugin');
        $this->assertFalse($this->pluginManager->hasPlugin('test-plugin'));
        $this->assertNull($this->pluginManager->getPlugin('test-plugin'));
    }

    public function testCanEnableAndDisablePlugin()
    {
        $plugin = $this->createMockPlugin('test-plugin', 'Test Plugin', '1.0.0');

        $this->pluginManager->register($plugin);
        $this->assertTrue($this->pluginManager->isPluginEnabled('test-plugin'));

        $this->pluginManager->disablePlugin('test-plugin');
        $this->assertFalse($this->pluginManager->isPluginEnabled('test-plugin'));

        $this->pluginManager->enablePlugin('test-plugin');
        $this->assertTrue($this->pluginManager->isPluginEnabled('test-plugin'));
    }

    public function testCannotEnablePluginWithUnsatisfiedDependencies()
    {
        $plugin = $this->createMockPlugin('test-plugin', 'Test Plugin', '1.0.0', ['missing-plugin']);

        $this->pluginManager->register($plugin);
        
        // Plugin should be registered but not enabled due to missing dependencies
        $this->assertTrue($this->pluginManager->hasPlugin('test-plugin'));
        $this->assertFalse($this->pluginManager->isPluginEnabled('test-plugin'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot enable plugin test-plugin: unsatisfied dependencies: missing-plugin');
        
        $this->pluginManager->enablePlugin('test-plugin');
    }

    public function testCanResolveDependencies()
    {
        $plugin1 = $this->createMockPlugin('plugin-1', 'Plugin 1', '1.0.0');
        $plugin2 = $this->createMockPlugin('plugin-2', 'Plugin 2', '1.0.0', ['plugin-1']);

        $this->pluginManager->register($plugin1);
        $this->pluginManager->register($plugin2);

        $dependencies = $this->pluginManager->resolveDependencies('plugin-2');

        $this->assertTrue($dependencies['plugin-1']);
        $this->assertTrue($dependencies['plugin-2']);
    }

    public function testDetectsCircularDependencies()
    {
        $plugin1 = $this->createMockPlugin('plugin-1', 'Plugin 1', '1.0.0', ['plugin-2']);
        $plugin2 = $this->createMockPlugin('plugin-2', 'Plugin 2', '1.0.0', ['plugin-1']);

        $this->pluginManager->register($plugin1);
        $this->pluginManager->register($plugin2);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Circular dependency detected involving plugin: plugin-1');
        
        $this->pluginManager->resolveDependencies('plugin-1');
    }

    public function testGetsPluginsInDependencyOrder()
    {
        $plugin1 = $this->createMockPlugin('plugin-1', 'Plugin 1', '1.0.0');
        $plugin2 = $this->createMockPlugin('plugin-2', 'Plugin 2', '1.0.0', ['plugin-1']);
        $plugin3 = $this->createMockPlugin('plugin-3', 'Plugin 3', '1.0.0', ['plugin-2']);

        $this->pluginManager->register($plugin1);
        $this->pluginManager->register($plugin2);
        $this->pluginManager->register($plugin3);

        $orderedPlugins = $this->pluginManager->getPluginsInDependencyOrder();
        $identifiers = array_keys($orderedPlugins);

        // plugin-1 should come before plugin-2, which should come before plugin-3
        $this->assertEquals('plugin-1', $identifiers[0]);
        $this->assertEquals('plugin-2', $identifiers[1]);
        $this->assertEquals('plugin-3', $identifiers[2]);
    }

    public function testValidatesPluginCompatibility()
    {
        // Compatible plugin
        $compatiblePlugin = $this->createMockPlugin('compatible', 'Compatible', '1.0.0');
        $this->assertTrue($this->pluginManager->validatePlugin($compatiblePlugin));

        // Incompatible plugin (wrong minimum version)
        $incompatiblePlugin = Mockery::mock(AuditPluginInterface::class);
        $incompatiblePlugin->shouldReceive('getIdentifier')->andReturn('incompatible');
        $incompatiblePlugin->shouldReceive('getMinimumWardenVersion')->andReturn('99.0.0');
        $incompatiblePlugin->shouldReceive('isCompatible')->andReturn(true);
        $incompatiblePlugin->shouldReceive('getAuditClasses')->andReturn([]);
        
        $this->assertFalse($this->pluginManager->validatePlugin($incompatiblePlugin));
    }

    public function testGetsAuditClassesFromEnabledPlugins()
    {
        $plugin1 = $this->createMockPlugin('plugin-1', 'Plugin 1', '1.0.0');
        $plugin1->shouldReceive('getAuditClasses')->andReturn(['AuditClass1', 'AuditClass2']);

        $plugin2 = $this->createMockPlugin('plugin-2', 'Plugin 2', '1.0.0');
        $plugin2->shouldReceive('getAuditClasses')->andReturn(['AuditClass3']);

        $this->pluginManager->register($plugin1);
        $this->pluginManager->register($plugin2);

        $auditClasses = $this->pluginManager->getAuditClasses();

        $this->assertCount(3, $auditClasses);
        $this->assertArrayHasKey('AuditClass1', $auditClasses);
        $this->assertArrayHasKey('AuditClass2', $auditClasses);
        $this->assertArrayHasKey('AuditClass3', $auditClasses);
    }

    public function testPluginConfiguration()
    {
        $plugin = $this->createMockPlugin('test-plugin', 'Test Plugin', '1.0.0');

        $this->pluginManager->register($plugin);

        // Default configuration
        $config = $this->pluginManager->getPluginConfig('test-plugin');
        $this->assertTrue($config['enabled']);
        $this->assertEquals(100, $config['priority']);

        // Set custom configuration
        $customConfig = ['enabled' => false, 'priority' => 200, 'custom' => 'value'];
        $this->pluginManager->setPluginConfig('test-plugin', $customConfig);

        $config = $this->pluginManager->getPluginConfig('test-plugin');
        $this->assertFalse($config['enabled']);
        $this->assertEquals(200, $config['priority']);
        $this->assertEquals('value', $config['custom']);
    }

    protected function createMockPlugin(string $identifier, string $name, string $version, array $dependencies = []): AuditPluginInterface
    {
        $plugin = Mockery::mock(AuditPluginInterface::class);
        $plugin->shouldReceive('getIdentifier')->andReturn($identifier);
        $plugin->shouldReceive('getName')->andReturn($name);
        $plugin->shouldReceive('getVersion')->andReturn($version);
        $plugin->shouldReceive('getAuthor')->andReturn('Test Author');
        $plugin->shouldReceive('getDescription')->andReturn('Test description');
        $plugin->shouldReceive('getDependencies')->andReturn($dependencies);
        $plugin->shouldReceive('getAuditClasses')->andReturn([]);
        $plugin->shouldReceive('isCompatible')->andReturn(true);
        $plugin->shouldReceive('getMinimumWardenVersion')->andReturn('2.0.0');
        $plugin->shouldReceive('getMaximumWardenVersion')->andReturn(null);
        $plugin->shouldReceive('getConfigSchema')->andReturn([]);
        $plugin->shouldReceive('initialize')->andReturn();
        $plugin->shouldReceive('cleanup')->andReturn();

        return $plugin;
    }
}