<?php

namespace Dgtlss\Warden\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Dgtlss\Warden\Providers\WardenServiceProvider;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Symfony\Component\Process\Process;
use Mockery;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        // Clear cache between tests
        Cache::flush();

        // Set default test configuration
        $this->setDefaultConfig();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    /**
     * Get package providers for the test.
     *
     * @param \Illuminate\Foundation\Application $app
     * @return array<int, string>
     */
    protected function getPackageProviders($app): array
    {
        return [WardenServiceProvider::class];
    }

    /**
     * Set default Warden configuration for tests.
     */
    protected function setDefaultConfig(): void
    {
        Config::set('warden.app_name', 'Test App');
        Config::set('warden.cache.enabled', false);
        Config::set('warden.cache.duration', 3600);
        Config::set('warden.cache.driver', 'array');
        Config::set('warden.audits.parallel_execution', false);
        Config::set('warden.audits.timeout', 60);
        Config::set('warden.audits.retry_attempts', 3);
        Config::set('warden.audits.retry_delay', 1000);
        Config::set('warden.sensitive_keys', ['APP_KEY', 'DB_PASSWORD']);
        Config::set('warden.notifications.slack.webhook_url', null);
        Config::set('warden.notifications.discord.webhook_url', null);
        Config::set('warden.notifications.teams.webhook_url', null);
        Config::set('warden.notifications.email.recipients', null);
    }

    /**
     * Load a test fixture file.
     *
     * @param string $name The fixture filename
     * @return string The fixture file contents
     * @throws \RuntimeException If fixture not found
     */
    protected function getFixture(string $name): string
    {
        $path = __DIR__ . '/Fixtures/' . $name;
        if (!file_exists($path)) {
            throw new \RuntimeException("Fixture not found: {$name} at path: {$path}");
        }
        $content = file_get_contents($path);
        if ($content === false) {
            throw new \RuntimeException("Failed to read fixture: {$name}");
        }
        return $content;
    }

    /**
     * Load a test fixture file and decode as array.
     *
     * @param string $name The fixture filename
     * @return array<mixed> The decoded fixture data
     */
    protected function getFixtureArray(string $name): array
    {
        $json = $this->getFixture($name);
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new \RuntimeException("Fixture is not valid JSON: {$name}");
        }
        return $data;
    }

    /**
     * Create a mocked Symfony Process with predefined output.
     *
     * @param string $output The process output
     * @param int $exitCode The process exit code
     * @param string $errorOutput The process error output
     * @return Process|\Mockery\MockInterface
     */
    protected function mockProcess(string $output, int $exitCode = 0, string $errorOutput = ''): object
    {
        $process = Mockery::mock(Process::class);
        $process->shouldReceive('setWorkingDirectory')->andReturnSelf();
        $process->shouldReceive('setTimeout')->andReturnSelf();
        $process->shouldReceive('run')->andReturn($exitCode);
        $process->shouldReceive('getOutput')->andReturn($output);
        $process->shouldReceive('getErrorOutput')->andReturn($errorOutput);
        $process->shouldReceive('getExitCode')->andReturn($exitCode);
        $process->shouldReceive('isSuccessful')->andReturn($exitCode === 0);

        return $process;
    }

    /**
     * Assert that a finding object has valid structure.
     *
     * @param \Dgtlss\Warden\ValueObjects\Finding $finding
     */
    protected function assertValidFinding($finding): void
    {
        $this->assertInstanceOf(\Dgtlss\Warden\ValueObjects\Finding::class, $finding);
        $this->assertNotEmpty($finding->source, 'Finding must have a source');
        $this->assertNotEmpty($finding->package, 'Finding must have a package');
        $this->assertNotEmpty($finding->title, 'Finding must have a title');
        $this->assertInstanceOf(\Dgtlss\Warden\Enums\Severity::class, $finding->severity);
    }

    /**
     * Assert that multiple findings are valid.
     *
     * @param array<int, \Dgtlss\Warden\ValueObjects\Finding> $findings
     */
    protected function assertValidFindings(array $findings): void
    {
        foreach ($findings as $finding) {
            $this->assertValidFinding($finding);
        }
    }
}
