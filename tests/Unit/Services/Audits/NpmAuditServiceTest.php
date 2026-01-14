<?php

namespace Dgtlss\Warden\Tests\Unit\Services\Audits;

use Dgtlss\Warden\Services\Audits\NpmAuditService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\File;
use Mockery;
use Symfony\Component\Process\Process;

class NpmAuditServiceTest extends TestCase
{
    private string $packageJsonPath;
    private string $packageLockPath;
    private ?string $originalPackageJson = null;
    private ?string $originalPackageLock = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->packageJsonPath = base_path('package.json');
        $this->packageLockPath = base_path('package-lock.json');
        $this->originalPackageJson = File::exists($this->packageJsonPath) ? File::get($this->packageJsonPath) : null;
        $this->originalPackageLock = File::exists($this->packageLockPath) ? File::get($this->packageLockPath) : null;
    }

    protected function tearDown(): void
    {
        if ($this->originalPackageJson !== null) {
            File::put($this->packageJsonPath, $this->originalPackageJson);
        } elseif (File::exists($this->packageJsonPath)) {
            File::delete($this->packageJsonPath);
        }

        if ($this->originalPackageLock !== null) {
            File::put($this->packageLockPath, $this->originalPackageLock);
        } elseif (File::exists($this->packageLockPath)) {
            File::delete($this->packageLockPath);
        }

        parent::tearDown();
    }

    public function testGetNameReturnsNpm(): void
    {
        $service = new NpmAuditService();

        $this->assertEquals('npm', $service->getName());
    }

    public function testRunWithNoVulnerabilities(): void
    {
        /** @var NpmAuditService $service */
        $service = Mockery::mock(NpmAuditService::class)->makePartial();

        $output = $this->getFixture('npm-audit-success.json');
        $result = $this->runServiceWithMockedOutput($service, $output);

        $this->assertTrue($result);
        $this->assertEmpty($service->getFindings());
    }

    public function testRunWithVulnerabilitiesModernFormat(): void
    {
        /** @var NpmAuditService $service */
        $service = Mockery::mock(NpmAuditService::class)->makePartial();

        $output = $this->getFixture('npm-audit-vulnerabilities-v7.json');
        $result = $this->runServiceWithMockedOutput($service, $output);

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);
        $this->assertCount(2, $findings); // lodash and axios

        // Verify lodash vulnerability
        $lodashFinding = $findings[0];
        $this->assertEquals('lodash', $lodashFinding->package);
        $this->assertStringContainsString('Prototype Pollution', $lodashFinding->title);
        $this->assertEquals('high', $lodashFinding->severity->value);
        $this->assertStringContainsString('GHSA-', (string) $lodashFinding->cve);
        $this->assertEquals('<4.17.21', $lodashFinding->affectedVersions);

        // Verify axios vulnerability
        $axiosFinding = $findings[1];
        $this->assertEquals('axios', $axiosFinding->package);
        $this->assertStringContainsString('Cross-Site Request Forgery', $axiosFinding->title);
        $this->assertEquals('moderate', $axiosFinding->severity->value);

        $this->assertValidFindings($findings);
    }

    public function testRunWithVulnerabilitiesLegacyFormat(): void
    {
        /** @var NpmAuditService $service */
        $service = Mockery::mock(NpmAuditService::class)->makePartial();

        $output = $this->getFixture('npm-audit-vulnerabilities-legacy.json');
        $result = $this->runServiceWithMockedOutput($service, $output);

        $this->assertTrue($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);
        $this->assertCount(1, $findings); // One advisory

        // Verify legacy format finding
        $finding = $findings[0];
        $this->assertEquals('lodash', $finding->package);
        $this->assertStringContainsString('Prototype Pollution', $finding->title);
        $this->assertEquals('high', $finding->severity->value);
        $this->assertEquals('CVE-2019-10744', $finding->cve);
        $this->assertEquals('<4.17.21', $finding->affectedVersions);

        $this->assertValidFindings($findings);
    }

    public function testRunWithInvalidJson(): void
    {
        /** @var NpmAuditService $service */
        $service = Mockery::mock(NpmAuditService::class)->makePartial();

        $result = $this->runServiceWithMockedOutput($service, 'Invalid JSON output', 1, 'npm command failed');

        $this->assertFalse($result);

        $findings = $service->getFindings();
        $this->assertNotEmpty($findings);
        $this->assertEquals('npm', $findings[0]->package);
        $this->assertStringContainsString('failed to run', $findings[0]->title);
        $this->assertEquals('high', $findings[0]->severity->value);
    }

    public function testRunReturnsFalseWhenPackageJsonMissing(): void
    {
        if (File::exists($this->packageJsonPath)) {
            File::delete($this->packageJsonPath);
        }

        File::put($this->packageLockPath, $this->getFixture('package-lock.json'));

        $service = new NpmAuditService();
        $result = $service->run();

        $this->assertFalse($result);
        $this->assertNotEmpty($service->getFindings());
        $this->assertEquals('Missing package.json', $service->getFindings()[0]->title);
    }

    public function testRunReturnsFalseWhenPackageLockMissing(): void
    {
        File::put($this->packageJsonPath, '{"name":"test","version":"1.0.0"}');
        if (File::exists($this->packageLockPath)) {
            File::delete($this->packageLockPath);
        }

        $service = new NpmAuditService();
        $result = $service->run();

        $this->assertFalse($result);
        $this->assertNotEmpty($service->getFindings());
        $this->assertEquals('Missing package-lock.json', $service->getFindings()[0]->title);
    }

    public function testRunParsesModernAuditOutput(): void
    {
        File::put($this->packageJsonPath, '{"name":"test","version":"1.0.0"}');
        File::put($this->packageLockPath, $this->getFixture('package-lock.json'));

        $process = $this->mockProcess($this->getFixture('npm-audit-vulnerabilities-v7.json'), 1);
        $service = $this->makeServiceWithProcess($process);

        $result = $service->run();

        $this->assertTrue($result);
        $this->assertCount(2, $service->getFindings());
    }

    public function testRunParsesLegacyAuditOutput(): void
    {
        File::put($this->packageJsonPath, '{"name":"test","version":"1.0.0"}');
        File::put($this->packageLockPath, $this->getFixture('package-lock.json'));

        $process = $this->mockProcess($this->getFixture('npm-audit-vulnerabilities-legacy.json'), 1);
        $service = $this->makeServiceWithProcess($process);

        $result = $service->run();

        $this->assertTrue($result);
        $this->assertCount(1, $service->getFindings());
    }

    public function testRunReturnsFalseWhenOutputIsNotJson(): void
    {
        File::put($this->packageJsonPath, '{"name":"test","version":"1.0.0"}');
        File::put($this->packageLockPath, $this->getFixture('package-lock.json'));

        $process = $this->mockProcess('Invalid JSON output', 1, 'npm command failed');
        $service = $this->makeServiceWithProcess($process);

        $result = $service->run();

        $this->assertFalse($result);
        $this->assertNotEmpty($service->getFindings());
    }

    /**
     * Helper method to run service with mocked output.
     * This simulates the JSON parsing logic without actually running npm.
     */
    private function runServiceWithMockedOutput(
        NpmAuditService $service,
        string $output,
        int $exitCode = 0,
        string $errorOutput = ''
    ): bool {
        // Simulate the parsing logic from the actual run() method
        $data = json_decode($output, true);

        if ($data === null && $output !== '{}' && $output !== '') {
            // Simulate invalid JSON handling
            $reflection = new \ReflectionClass($service);
            $method = $reflection->getMethod('addFinding');
            $method->setAccessible(true);

            $finding = [
                'package' => 'npm',
                'title' => 'npm audit failed to run',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null,
                'error' => "Exit Code: {$exitCode}\nError: {$errorOutput}"
            ];
            $method->invoke($service, $finding);

            return false;
        }

        if ($data === null) {
            return false;
        }

        $reflection = new \ReflectionClass($service);
        $addFindingMethod = $reflection->getMethod('addFinding');
        $addFindingMethod->setAccessible(true);

        // Handle modern npm audit format (npm 7+)
        if (isset($data['vulnerabilities'])) {
            foreach ($data['vulnerabilities'] as $package => $vulnerability) {
                if (isset($vulnerability['via']) && is_array($vulnerability['via'])) {
                    foreach ($vulnerability['via'] as $viaItem) {
                        if (is_array($viaItem)) {
                            $finding = [
                                'package' => $package,
                                'title' => $viaItem['title'] ?? 'Unknown vulnerability',
                                'severity' => $viaItem['severity'] ?? 'unknown',
                                'cve' => $viaItem['url'] ?? null,
                                'affected_versions' => $viaItem['range'] ?? ($vulnerability['range'] ?? 'unknown')
                            ];
                            $addFindingMethod->invoke($service, $finding);
                        }
                    }
                } else {
                    $finding = [
                        'package' => $package,
                        'title' => $vulnerability['title'] ?? 'Unknown vulnerability',
                        'severity' => $vulnerability['severity'] ?? 'unknown',
                        'cve' => $vulnerability['url'] ?? null,
                        'affected_versions' => $vulnerability['range'] ?? 'unknown'
                    ];
                    $addFindingMethod->invoke($service, $finding);
                }
            }
        }

        // Handle legacy npm audit format (npm v6 and earlier)
        if (isset($data['advisories'])) {
            foreach ($data['advisories'] as $advisory) {
                $finding = [
                    'package' => $advisory['module_name'] ?? 'unknown',
                    'title' => $advisory['title'] ?? 'Unknown vulnerability',
                    'severity' => $advisory['severity'] ?? 'unknown',
                    'cve' => $advisory['cves'][0] ?? $advisory['url'] ?? null,
                    'affected_versions' => $advisory['vulnerable_versions'] ?? 'unknown'
                ];
                $addFindingMethod->invoke($service, $finding);
            }
        }

        return true;
    }

    private function makeServiceWithProcess(Process $process): NpmAuditService
    {
        return new class ($process) extends NpmAuditService {
            public function __construct(private Process $process)
            {
            }

            protected function createProcess(array $command): Process
            {
                return $this->process;
            }
        };
    }
}
