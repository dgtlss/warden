<?php

namespace Dgtlss\Warden\Tests\Services;

use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\Services\Audits\DockerAuditService;
use Symfony\Component\Process\Process;
use Illuminate\Support\Facades\Log;

class DockerAuditServiceTest extends TestCase
{
    protected DockerAuditService $auditService;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->auditService = new DockerAuditService();
        $this->auditService->initialize([
            'enabled' => true,
            'timeout' => 30,
            'scan_dockerfile' => true,
            'scan_docker_compose' => true,
            'scan_images' => false, // Disable for testing to avoid Docker dependency
            'check_secrets' => true,
            'check_base_images' => true,
        ]);
    }

    public function testGetName()
    {
        $this->assertEquals('Docker Security Audit', $this->auditService->getName());
    }

    public function testDefaultConfig()
    {
        $service = new DockerAuditService();
        $service->initialize();
        $config = $service->getConfig();
        
        $this->assertTrue($config['enabled']);
        $this->assertEquals(600, $config['timeout']);
        $this->assertTrue($config['scan_images']);
        $this->assertTrue($config['scan_dockerfile']);
        $this->assertTrue($config['scan_docker_compose']);
        $this->assertEquals('medium', $config['severity_threshold']);
    }

    public function testShouldRunWithoutDockerFiles()
    {
        // Mock that no Docker files exist
        $service = $this->createPartialMock(DockerAuditService::class, ['isDockerAvailable']);
        $service->method('isDockerAvailable')->willReturn(true);
        $service->initialize();
        
        // This should return false when no Docker files exist
        $this->assertFalse($service->shouldRun());
    }

    public function testShouldRunWithDockerAvailable()
    {
        $service = $this->createPartialMock(DockerAuditService::class, ['isDockerAvailable']);
        $service->method('isDockerAvailable')->willReturn(true);
        $service->initialize();
        
        // Create temporary Dockerfile for testing
        $tempDockerfile = tempnam(sys_get_temp_dir(), 'Dockerfile');
        file_put_contents($tempDockerfile, 'FROM nginx:latest');
        
        // Mock the base_path function to return our temp file
        if (!function_exists('base_path')) {
            function base_path($path) {
                global $tempDockerfile;
                return $path === 'Dockerfile' ? $tempDockerfile : '/tmp';
            }
        }
        
        $this->assertTrue($service->shouldRun());
        
        // Cleanup
        unlink($tempDockerfile);
    }

    public function testShouldNotRunWithoutDocker()
    {
        $service = $this->createPartialMock(DockerAuditService::class, ['isDockerAvailable']);
        $service->method('isDockerAvailable')->willReturn(false);
        $service->initialize();
        
        $this->assertFalse($service->shouldRun());
    }

    public function testCheckDockerfileSecrets()
    {
        $dockerfileContent = '
FROM nginx:latest
ENV PASSWORD=secret123
ENV API_KEY=abc123def456
COPY . /app
';
        
        // Create temporary Dockerfile
        $tempDockerfile = tempnam(sys_get_temp_dir(), 'Dockerfile');
        file_put_contents($tempDockerfile, $dockerfileContent);
        
        // Mock base_path function
        if (!function_exists('base_path')) {
            function base_path($path) {
                global $tempDockerfile;
                return $path === 'Dockerfile' ? $tempDockerfile : '/tmp';
            }
        }
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        // Should find secrets in Dockerfile
        $this->assertNotEmpty($findings);
        $secretFindings = array_filter($findings, fn($f) => $f['package'] === 'dockerfile-secrets');
        $this->assertNotEmpty($secretFindings);
        
        // Cleanup
        unlink($tempDockerfile);
    }

    public function testCheckBaseImages()
    {
        $dockerfileContent = '
FROM scratch
FROM busybox:latest
FROM nginx:latest
FROM ubuntu:20.04
';
        
        // Create temporary Dockerfile
        $tempDockerfile = tempnam(sys_get_temp_dir(), 'Dockerfile');
        file_put_contents($tempDockerfile, $dockerfileContent);
        
        // Mock base_path function
        if (!function_exists('base_path')) {
            function base_path($path) {
                global $tempDockerfile;
                return $path === 'Dockerfile' ? $tempDockerfile : '/tmp';
            }
        }
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        // Should find issues with scratch and busybox
        $this->assertNotEmpty($findings);
        $baseImageFindings = array_filter($findings, fn($f) => 
            $f['package'] === 'scratch' || $f['package'] === 'busybox:latest'
        );
        $this->assertNotEmpty($baseImageFindings);
        
        // Should find latest tag issue
        $latestTagFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'Latest Tag') !== false
        );
        $this->assertNotEmpty($latestTagFindings);
        
        // Cleanup
        unlink($tempDockerfile);
    }

    public function testCheckInsecureDockerfilePractices()
    {
        $dockerfileContent = '
FROM nginx:latest
USER root
RUN apt-get update && apt-get install -y sudo
EXPOSE 80
EXPOSE 443
';
        
        // Create temporary Dockerfile
        $tempDockerfile = tempnam(sys_get_temp_dir(), 'Dockerfile');
        file_put_contents($tempDockerfile, $dockerfileContent);
        
        // Mock base_path function
        if (!function_exists('base_path')) {
            function base_path($path) {
                global $tempDockerfile;
                return $path === 'Dockerfile' ? $tempDockerfile : '/tmp';
            }
        }
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        // Should find root user issue
        $rootUserFindings = array_filter($findings, fn($f) => 
            $f['package'] === 'dockerfile-user-root'
        );
        $this->assertNotEmpty($rootUserFindings);
        
        // Should find sudo usage issue
        $sudoFindings = array_filter($findings, fn($f) => 
            $f['package'] === 'dockerfile-sudo'
        );
        $this->assertNotEmpty($sudoFindings);
        
        // Should find privileged ports issue
        $privilegedPortsFindings = array_filter($findings, fn($f) => 
            $f['package'] === 'dockerfile-privileged-ports'
        );
        $this->assertNotEmpty($privilegedPortsFindings);
        
        // Cleanup
        unlink($tempDockerfile);
    }

    public function testCheckDockerComposeSecrets()
    {
        $dockerComposeContent = '
version: "3.8"
services:
  app:
    image: nginx:latest
    environment:
      - PASSWORD=secret123
      - DATABASE_URL=postgresql://user:pass@localhost/db
      - API_KEY=abc123def456
';
        
        // Create temporary docker-compose.yml
        $tempComposeFile = tempnam(sys_get_temp_dir(), 'docker-compose.yml');
        file_put_contents($tempComposeFile, $dockerComposeContent);
        
        // Mock base_path function
        if (!function_exists('base_path')) {
            function base_path($path) {
                global $tempComposeFile;
                return $path === 'docker-compose.yml' ? $tempComposeFile : '/tmp';
            }
        }
        
        $this->auditService->run();
        $findings = $this->auditService->getFindings();
        
        // Should find secrets in docker-compose.yml
        $this->assertNotEmpty($findings);
        $composeSecretFindings = array_filter($findings, fn($f) => $f['package'] === 'docker-compose-secrets');
        $this->assertNotEmpty($composeSecretFindings);
        
        // Cleanup
        unlink($tempComposeFile);
    }

    public function testShouldExcludeImage()
    {
        $service = new DockerAuditService();
        $service->initialize([
            'exclude_images' => ['test/*', 'internal-*']
        ]);
        
        // Use reflection to access protected method
        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('shouldExcludeImage');
        $method->setAccessible(true);
        
        $this->assertTrue($method->invoke($service, 'test/app'));
        $this->assertTrue($method->invoke($service, 'internal-database'));
        $this->assertFalse($method->invoke($service, 'nginx:latest'));
        $this->assertFalse($method->invoke($service, 'ubuntu:20.04'));
    }

    public function testProcessVulnerabilities()
    {
        $service = new DockerAuditService();
        $service->initialize(['severity_threshold' => 'high']);
        
        $vulnerabilities = [
            [
                'Title' => 'Test Low Severity',
                'Description' => 'A low severity vulnerability',
                'Severity' => 'LOW',
                'VulnerabilityID' => 'CVE-2021-0001',
                'InstalledVersion' => '1.0.0',
                'FixedVersion' => '1.0.1',
                'PrimaryURL' => 'https://example.com/cve-2021-0001',
            ],
            [
                'Title' => 'Test High Severity',
                'Description' => 'A high severity vulnerability',
                'Severity' => 'HIGH',
                'VulnerabilityID' => 'CVE-2021-0002',
                'InstalledVersion' => '2.0.0',
                'FixedVersion' => '2.0.1',
                'PrimaryURL' => 'https://example.com/cve-2021-0002',
            ],
        ];
        
        // Use reflection to access protected method
        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('processVulnerabilities');
        $method->setAccessible(true);
        
        $method->invoke($service, 'test-image', $vulnerabilities);
        $findings = $service->getFindings();
        
        // Should only include high severity vulnerability
        $this->assertCount(1, $findings);
        $this->assertEquals('Test High Severity', $findings[0]['title']);
        $this->assertEquals('high', $findings[0]['severity']);
        $this->assertEquals('CVE-2021-0002', $findings[0]['cve']);
    }

    public function testIsDockerAvailable()
    {
        $service = new DockerAuditService();
        
        // Use reflection to access protected method
        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('isDockerAvailable');
        $method->setAccessible(true);
        
        // This test will pass if Docker is installed, fail otherwise
        // In a real test environment, you might want to mock this
        $result = $method->invoke($service);
        $this->assertIsBool($result);
    }
}