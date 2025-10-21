<?php

namespace Dgtlss\Warden\Tests\Services\Dependencies;

use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\Services\Dependencies\DependencyResolver;
use Dgtlss\Warden\Services\Dependencies\PhpExtensionDependency;
use Dgtlss\Warden\Services\Dependencies\SystemCommandDependency;
use Dgtlss\Warden\Services\Dependencies\FileDependency;
use Dgtlss\Warden\Contracts\PluginManagerInterface;
use Mockery;

class DependencyResolverTest extends TestCase
{
    protected DependencyResolver $resolver;
    protected PluginManagerInterface $pluginManager;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->pluginManager = Mockery::mock(PluginManagerInterface::class);
        $this->resolver = new DependencyResolver($this->pluginManager);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function testCanAddDependency()
    {
        $dependency = new PhpExtensionDependency('json');
        
        $this->resolver->addDependency($dependency);
        
        $dependencies = $this->resolver->getDependencies();
        $this->assertCount(1, $dependencies);
        $this->assertArrayHasKey('php-extension-json', $dependencies);
    }

    public function testCanRemoveDependency()
    {
        $dependency = new PhpExtensionDependency('json');
        
        $this->resolver->addDependency($dependency);
        $this->assertCount(1, $this->resolver->getDependencies());
        
        $this->resolver->removeDependency('php-extension-json');
        $this->assertCount(0, $this->resolver->getDependencies());
    }

    public function testCanGetDependenciesByType()
    {
        $phpDep = new PhpExtensionDependency('json');
        $commandDep = new SystemCommandDependency('composer');
        $fileDep = new FileDependency('composer.json');
        
        $this->resolver->addDependency($phpDep);
        $this->resolver->addDependency($commandDep);
        $this->resolver->addDependency($fileDep);
        
        $phpDeps = $this->resolver->getDependenciesByType('php-extension');
        $commandDeps = $this->resolver->getDependenciesByType('system-command');
        $fileDeps = $this->resolver->getDependenciesByType('file');
        
        $this->assertCount(1, $phpDeps);
        $this->assertCount(1, $commandDeps);
        $this->assertCount(1, $fileDeps);
    }

    public function testChecksIfDependencyIsSatisfied()
    {
        // json extension should be available in most PHP installations
        $jsonDep = new PhpExtensionDependency('json');
        $this->resolver->addDependency($jsonDep);
        
        $this->assertTrue($this->resolver->isSatisfied('php-extension-json'));
        
        // Non-existent extension should not be satisfied
        $fakeDep = new PhpExtensionDependency('non-existent-extension-12345');
        $this->resolver->addDependency($fakeDep);
        
        $this->assertFalse($this->resolver->isSatisfied('php-extension-non-existent-extension-12345'));
    }

    public function testGetsUnsatisfiedDependencies()
    {
        $satisfiedDep = new PhpExtensionDependency('json'); // Should be available
        $unsatisfiedDep = new PhpExtensionDependency('non-existent-extension-12345');
        
        $this->resolver->addDependency($satisfiedDep);
        $this->resolver->addDependency($unsatisfiedDep);
        
        $unsatisfied = $this->resolver->getUnsatisfiedDependencies();
        
        $this->assertCount(1, $unsatisfied);
        $this->assertArrayHasKey('php-extension-non-existent-extension-12345', $unsatisfied);
    }

    public function testGetsUnsatisfiedDependenciesByType()
    {
        $phpDep = new PhpExtensionDependency('non-existent-extension-12345');
        $commandDep = new SystemCommandDependency('non-existent-command-12345');
        
        $this->resolver->addDependency($phpDep);
        $this->resolver->addDependency($commandDep);
        
        $grouped = $this->resolver->getUnsatisfiedDependenciesByType();
        
        $this->assertArrayHasKey('php-extension', $grouped);
        $this->assertArrayHasKey('system-command', $grouped);
        $this->assertCount(1, $grouped['php-extension']);
        $this->assertCount(1, $grouped['system-command']);
    }

    public function testResolvesAllDependencies()
    {
        $satisfiedDep = new PhpExtensionDependency('json'); // Should be satisfied
        $unsatisfiedDep = new PhpExtensionDependency('non-existent-extension-12345');
        
        $this->resolver->addDependency($satisfiedDep);
        $this->resolver->addDependency($unsatisfiedDep);
        
        $results = $this->resolver->resolveAll();
        
        $this->assertTrue($results['php-extension-json']);
        $this->assertFalse($results['php-extension-non-existent-extension-12345']);
    }

    public function testGetsResolutionReport()
    {
        $satisfiedDep = new PhpExtensionDependency('json');
        $unsatisfiedDep = new PhpExtensionDependency('non-existent-extension-12345');
        
        $this->resolver->addDependency($satisfiedDep);
        $this->resolver->addDependency($unsatisfiedDep);
        
        $report = $this->resolver->getResolutionReport();
        
        $this->assertEquals(2, $report['total']);
        $this->assertEquals(1, $report['satisfied']);
        $this->assertEquals(1, $report['unsatisfied']);
        $this->assertEquals(0, $report['resolvable']); // PHP extensions can't be auto-resolved
        $this->assertEquals(1, $report['unresolvable']);
        
        $this->assertArrayHasKey('php-extension-json', $report['details']);
        $this->assertArrayHasKey('php-extension-non-existent-extension-12345', $report['details']);
    }

    public function testCreatesPhpExtensionDependency()
    {
        $dep = $this->resolver->createPhpExtensionDependency('json', 200);
        
        $this->assertInstanceOf(PhpExtensionDependency::class, $dep);
        $this->assertEquals('php-extension-json', $dep->getIdentifier());
        $this->assertEquals('php-extension', $dep->getType());
        $this->assertEquals(200, $dep->getPriority());
    }

    public function testCreatesSystemCommandDependency()
    {
        $dep = $this->resolver->createSystemCommandDependency(
            'composer',
            ['--version'],
            'curl -sS https://getcomposer.org/installer | php',
            150
        );
        
        $this->assertInstanceOf(SystemCommandDependency::class, $dep);
        $this->assertEquals('command-composer', $dep->getIdentifier());
        $this->assertEquals('system-command', $dep->getType());
        $this->assertEquals(150, $dep->getPriority());
    }

    public function testCreatesFileDependency()
    {
        $dep = $this->resolver->createFileDependency('composer.json', true, false, 100);
        
        $this->assertInstanceOf(FileDependency::class, $dep);
        $this->assertEquals('file-composer.json', $dep->getIdentifier());
        $this->assertEquals('file', $dep->getType());
        $this->assertEquals(100, $dep->getPriority());
    }

    public function testCreatesPluginDependency()
    {
        $this->pluginManager
            ->shouldReceive('hasPlugin')
            ->with('test-plugin')
            ->andReturn(true);
            
        $this->pluginManager
            ->shouldReceive('isPluginEnabled')
            ->with('test-plugin')
            ->andReturn(true);
            
        $plugin = Mockery::mock(\Dgtlss\Warden\Contracts\AuditPluginInterface::class);
        $plugin->shouldReceive('getVersion')->andReturn('1.0.0');
        
        $this->pluginManager
            ->shouldReceive('getPlugin')
            ->with('test-plugin')
            ->andReturn($plugin);

        $dep = $this->resolver->createPluginDependency('test-plugin', '1.0.0', 50);
        
        $this->assertInstanceOf(\Dgtlss\Warden\Services\Dependencies\PluginDependency::class, $dep);
        $this->assertEquals('plugin-test-plugin', $dep->getIdentifier());
        $this->assertEquals('plugin', $dep->getType());
        $this->assertEquals(50, $dep->getPriority());
    }
}