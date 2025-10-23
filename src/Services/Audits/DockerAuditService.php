<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Illuminate\Support\Facades\Log;
use Exception;

class DockerAuditService extends AbstractAuditService
{
    protected string $dockerfilePath = 'Dockerfile';
    protected string $dockerComposePath = 'docker-compose.yml';
    protected array $dockerImages = [];

    public function getName(): string
    {
        return 'Docker Security Audit';
    }

    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'dockerfile_path' => env('WARDEN_DOCKERFILE_PATH', 'Dockerfile'),
            'docker_compose_path' => env('WARDEN_DOCKER_COMPOSE_PATH', 'docker-compose.yml'),
            'scan_images' => env('WARDEN_DOCKER_SCAN_IMAGES', true),
            'scan_dockerfile' => env('WARDEN_DOCKER_SCAN_DOCKERFILE', true),
            'scan_docker_compose' => env('WARDEN_DOCKER_SCAN_DOCKER_COMPOSE', true),
            'check_base_images' => env('WARDEN_DOCKER_CHECK_BASE_IMAGES', true),
            'check_secrets' => env('WARDEN_DOCKER_CHECK_SECRETS', true),
            'check_vulnerabilities' => env('WARDEN_DOCKER_CHECK_VULNERABILITIES', true),
            'severity_threshold' => env('WARDEN_DOCKER_SEVERITY_THRESHOLD', 'medium'), // low, medium, high, critical
            'timeout' => env('WARDEN_DOCKER_TIMEOUT', 600), // 10 minutes for Docker scans
            'exclude_images' => env('WARDEN_DOCKER_EXCLUDE_IMAGES') ? explode(',', env('WARDEN_DOCKER_EXCLUDE_IMAGES')) : [],
            'custom_registry_urls' => env('WARDEN_DOCKER_CUSTOM_REGISTRY_URLS') ? explode(',', env('WARDEN_DOCKER_CUSTOM_REGISTRY_URLS')) : [],
        ]);
    }

    protected function onInitialize(): void
    {
        $this->dockerfilePath = $this->getConfigValue('dockerfile_path', 'Dockerfile');
        $this->dockerComposePath = $this->getConfigValue('docker_compose_path', 'docker-compose.yml');
    }

    protected function onShouldRun(): bool
    {
        // Check if Docker is available
        if (!$this->isDockerAvailable()) {
            $this->warning('Docker is not available or not running');
            return false;
        }

        // Check if any Docker-related files exist
        $hasDockerfile = file_exists(base_path($this->dockerfilePath));
        $hasDockerCompose = file_exists(base_path($this->dockerComposePath));
        
        if (!$hasDockerfile && !$hasDockerCompose) {
            $this->info('No Docker files found, skipping Docker audit');
            return false;
        }

        return true;
    }

    public function run(): bool
    {
        try {
            $this->info('Starting Docker security audit');

            // Scan Dockerfile if it exists and is enabled
            if ($this->getConfigValue('scan_dockerfile', true) && file_exists(base_path($this->dockerfilePath))) {
                $this->scanDockerfile();
            }

            // Scan docker-compose.yml if it exists and is enabled
            if ($this->getConfigValue('scan_docker_compose', true) && file_exists(base_path($this->dockerComposePath))) {
                $this->scanDockerCompose();
            }

            // Scan Docker images if enabled
            if ($this->getConfigValue('scan_images', true)) {
                $this->scanDockerImages();
            }

            $this->info('Docker security audit completed');
            return empty($this->findings);

        } catch (Exception $e) {
            $this->error('Docker audit failed: ' . $e->getMessage());
            $this->addFinding([
                'package' => 'docker-audit',
                'title' => 'Docker Audit Failed',
                'description' => 'The Docker security audit encountered an error: ' . $e->getMessage(),
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => null,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    protected function scanDockerfile(): void
    {
        $dockerfile = base_path($this->dockerfilePath);
        $content = file_get_contents($dockerfile);

        $this->info('Scanning Dockerfile for security issues');

        // Check for secrets in Dockerfile
        if ($this->getConfigValue('check_secrets', true)) {
            $this->checkDockerfileSecrets($content);
        }

        // Check base image vulnerabilities
        if ($this->getConfigValue('check_base_images', true)) {
            $this->checkBaseImages($content);
        }

        // Check for insecure practices
        $this->checkInsecureDockerfilePractices($content);
    }

    protected function scanDockerCompose(): void
    {
        $dockerCompose = base_path($this->dockerComposePath);
        $content = file_get_contents($dockerCompose);

        $this->info('Scanning docker-compose.yml for security issues');

        // Check for secrets in docker-compose.yml
        if ($this->getConfigValue('check_secrets', true)) {
            $this->checkDockerComposeSecrets($content);
        }

        // Extract images from docker-compose for scanning
        $this->extractImagesFromDockerCompose($content);
    }

    protected function scanDockerImages(): void
    {
        $this->info('Scanning Docker images for vulnerabilities');

        // Get images to scan
        $images = $this->getImagesToScan();

        foreach ($images as $image) {
            if ($this->shouldExcludeImage($image)) {
                $this->debug("Skipping excluded image: {$image}");
                continue;
            }

            $this->scanImageForVulnerabilities($image);
        }
    }

    protected function checkDockerfileSecrets(string $content): void
    {
        $secretPatterns = [
            '/password\s*=\s*["\']?([^"\'\s]+)/i',
            '/secret\s*=\s*["\']?([^"\'\s]+)/i',
            '/api[_-]?key\s*=\s*["\']?([^"\'\s]+)/i',
            '/token\s*=\s*["\']?([^"\'\s]+)/i',
            '/aws[_-]?access[_-]?key\s*=\s*["\']?([^"\'\s]+)/i',
            '/aws[_-]?secret[_-]?key\s*=\s*["\']?([^"\'\s]+)/i',
        ];

        foreach ($secretPatterns as $pattern) {
            if (preg_match($pattern, $content, $matches)) {
                $this->addFinding([
                    'package' => 'dockerfile-secrets',
                    'title' => 'Potential Secret Found in Dockerfile',
                    'description' => "A potential secret or credential was found in the Dockerfile. This should be avoided and use environment variables or secrets management instead.",
                    'severity' => 'critical',
                    'cve' => null,
                    'affected_versions' => 'all',
                    'fix_version' => null,
                    'link' => 'https://docs.docker.com/develop/dev-best-practices/#secrets',
                ]);
            }
        }
    }

    protected function checkBaseImages(string $content): void
    {
        // Extract FROM instructions
        preg_match_all('/FROM\s+([^\s\n]+)/i', $content, $matches);

        foreach ($matches[1] as $baseImage) {
            // Remove tag if present to get base image name
            $imageName = explode(':', $baseImage)[0];

            // Check for known problematic base images
            $insecureBaseImages = [
                'scratch' => 'Using scratch as base image provides no security updates',
                'busybox' => 'BusyBox images may not receive regular security updates',
            ];

            if (isset($insecureBaseImages[$imageName])) {
                $this->addFinding([
                    'package' => $baseImage,
                    'title' => 'Potentially Insecure Base Image',
                    'description' => $insecureBaseImages[$imageName],
                    'severity' => 'medium',
                    'cve' => null,
                    'affected_versions' => 'all',
                    'fix_version' => null,
                    'link' => 'https://docs.docker.com/develop/dev-best-practices/#base-image',
                ]);
            }

            // Check for latest tag
            if (strpos($baseImage, ':latest') !== false || strpos($baseImage, ':') === false) {
                $this->addFinding([
                    'package' => $baseImage,
                    'title' => 'Using Latest Tag in Base Image',
                    'description' => 'Using the "latest" tag can lead to unpredictable builds and potential security issues. Use specific version tags instead.',
                    'severity' => 'medium',
                    'cve' => null,
                    'affected_versions' => 'all',
                    'fix_version' => null,
                    'link' => 'https://docs.docker.com/develop/dev-best-practices/#tag-your-images',
                ]);
            }
        }
    }

    protected function checkInsecureDockerfilePractices(string $content): void
    {
        $issues = [];

        // Check for running as root
        if (preg_match('/USER\s+root/i', $content) && !preg_match('/USER\s+(?!root)/i', $content)) {
            $issues[] = [
                'package' => 'dockerfile-user-root',
                'title' => 'Container Running as Root User',
                'description' => 'Running containers as root user is a security risk. Create and use a non-root user.',
                'severity' => 'high',
                'link' => 'https://docs.docker.com/develop/dev-best-practices/#user',
            ];
        }

        // Check for sudo usage
        if (preg_match('/sudo/i', $content)) {
            $issues[] = [
                'package' => 'dockerfile-sudo',
                'title' => 'Sudo Usage in Dockerfile',
                'description' => 'Using sudo in Dockerfile can be a security risk. Avoid sudo usage if possible.',
                'severity' => 'medium',
                'link' => 'https://docs.docker.com/develop/dev-best-practices/#sudo',
            ];
        }

        // Check for exposed privileged ports
        if (preg_match('/EXPOSE\s+(.*\b(80|443|22|21|23|25|53|110|143|993|995)\b)/i', $content)) {
            $issues[] = [
                'package' => 'dockerfile-privileged-ports',
                'title' => 'Exposed Privileged Ports',
                'description' => 'Exposing privileged ports (< 1024) may require root privileges and can be a security risk.',
                'severity' => 'medium',
                'link' => 'https://docs.docker.com/develop/dev-best-practices/#expose-ports',
            ];
        }

        foreach ($issues as $issue) {
            $this->addFinding(array_merge($issue, [
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
            ]));
        }
    }

    protected function checkDockerComposeSecrets(string $content): void
    {
        $secretPatterns = [
            '/password:\s*["\']?([^"\'\s]+)/i',
            '/secret:\s*["\']?([^"\'\s]+)/i',
            '/api[_-]?key:\s*["\']?([^"\'\s]+)/i',
            '/token:\s*["\']?([^"\'\s]+)/i',
        ];

        foreach ($secretPatterns as $pattern) {
            if (preg_match($pattern, $content, $matches)) {
                $this->addFinding([
                    'package' => 'docker-compose-secrets',
                    'title' => 'Potential Secret Found in Docker Compose',
                    'description' => "A potential secret or credential was found in the docker-compose.yml file. Use environment variables or Docker secrets instead.",
                    'severity' => 'critical',
                    'cve' => null,
                    'affected_versions' => 'all',
                    'fix_version' => null,
                    'link' => 'https://docs.docker.com/compose/environment-variables/',
                ]);
            }
        }
    }

    protected function extractImagesFromDockerCompose(string $content): void
    {
        // Simple regex to extract image names from docker-compose.yml
        preg_match_all('/image:\s*([^\s\n]+)/i', $content, $matches);

        foreach ($matches[1] as $image) {
            $this->dockerImages[] = trim($image);
        }
    }

    protected function getImagesToScan(): array
    {
        $images = $this->dockerImages;

        // Add images from Dockerfile FROM instructions
        if (file_exists(base_path($this->dockerfilePath))) {
            $content = file_get_contents(base_path($this->dockerfilePath));
            preg_match_all('/FROM\s+([^\s\n]+)/i', $content, $matches);
            $images = array_merge($images, $matches[1]);
        }

        return array_unique($images);
    }

    protected function shouldExcludeImage(string $image): bool
    {
        $excludePatterns = $this->getConfigValue('exclude_images', []);
        
        foreach ($excludePatterns as $pattern) {
            if (fnmatch($pattern, $image)) {
                return true;
            }
        }

        return false;
    }

    protected function scanImageForVulnerabilities(string $image): void
    {
        if (!$this->getConfigValue('check_vulnerabilities', true)) {
            return;
        }

        $this->info("Scanning image: {$image}");

        try {
            // Use docker scout or docker run with security scanner
            $process = new Process(['docker', 'scout', 'cves', '--format', 'json', $image]);
            $process->setTimeout($this->getTimeout());
            $process->run();

            if (!$process->isSuccessful()) {
                // Fallback to docker run with trivy if available
                $this->scanWithTrivy($image);
                return;
            }

            $output = $process->getOutput();
            $vulnerabilities = json_decode($output, true);

            if ($vulnerabilities && isset($vulnerabilities['vulnerabilities'])) {
                $this->processVulnerabilities($image, $vulnerabilities['vulnerabilities']);
            }

        } catch (Exception $e) {
            $this->warning("Failed to scan image {$image}: " . $e->getMessage());
        }
    }

    protected function scanWithTrivy(string $image): void
    {
        try {
            $process = new Process(['docker', 'run', '--rm', '-v', '/var/run/docker.sock:/var/run/docker.sock', 'aquasec/trivy:latest', 'image', '--format', 'json', $image]);
            $process->setTimeout($this->getTimeout());
            $process->run();

            if (!$process->isSuccessful()) {
                $this->warning("Trivy scan failed for image {$image}");
                return;
            }

            $output = $process->getOutput();
            $scanResult = json_decode($output, true);

            if ($scanResult && isset($scanResult['Results'])) {
                foreach ($scanResult['Results'] as $result) {
                    if (isset($result['Vulnerabilities'])) {
                        $this->processVulnerabilities($image, $result['Vulnerabilities']);
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning("Trivy scan failed for image {$image}: " . $e->getMessage());
        }
    }

    protected function processVulnerabilities(string $image, array $vulnerabilities): void
    {
        $threshold = $this->getConfigValue('severity_threshold', 'medium');
        $severityLevels = ['low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        $minLevel = $severityLevels[$threshold] ?? 2;

        foreach ($vulnerabilities as $vuln) {
            $severity = strtolower($vuln['Severity'] ?? 'unknown');
            $level = $severityLevels[$severity] ?? 0;

            if ($level < $minLevel) {
                continue;
            }

            $this->addFinding([
                'package' => $image,
                'title' => $vuln['Title'] ?? 'Container Vulnerability',
                'description' => $vuln['Description'] ?? 'Security vulnerability found in container image',
                'severity' => $severity,
                'cve' => $vuln['VulnerabilityID'] ?? null,
                'affected_versions' => $vuln['InstalledVersion'] ?? 'unknown',
                'fix_version' => $vuln['FixedVersion'] ?? null,
                'link' => $vuln['PrimaryURL'] ?? null,
            ]);
        }
    }

    protected function isDockerAvailable(): bool
    {
        try {
            $process = new Process(['docker', '--version']);
            $process->run();
            return $process->isSuccessful();
        } catch (Exception $e) {
            return false;
        }
    }
}