<?php

namespace Dgtlss\Warden\Examples;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\Audits\AbstractAuditService;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\ValueObjects\Remediation;

/**
 * Example audit service that checks for Docker security issues.
 *
 * This demonstrates how to create a custom audit service for a Warden plugin.
 * It checks for common Docker security misconfigurations:
 *
 * - Docker socket exposure to web server
 * - Docker Compose files with privileged containers
 * - Exposed Docker API ports
 *
 * @example
 * ```php
 * // In your plugin's audits() method:
 * public function audits(): array
 * {
 *     return [DockerAuditService::class];
 * }
 * ```
 */
class DockerAuditService extends AbstractAuditService
{
    public function getName(): string
    {
        return 'Docker Security';
    }

    public function run(): bool
    {
        $this->checkDockerSocketExposure();
        $this->checkPrivilegedContainers();
        $this->checkExposedDockerApi();

        return $this->findings === [];
    }

    /**
     * Check if Docker socket is exposed to web processes.
     */
    protected function checkDockerSocketExposure(): void
    {
        $socketPath = '/var/run/docker.sock';

        if (!file_exists($socketPath)) {
            return;
        }

        $perms = fileperms($socketPath);
        if ($perms === false) {
            return;
        }

        $worldReadable = ($perms & 0x0004) !== 0;
        $worldWritable = ($perms & 0x0002) !== 0;

        if ($worldReadable || $worldWritable) {
            $this->addFinding(Finding::create(
                source: $this->getName(),
                package: 'docker',
                title: 'Docker socket has permissive permissions',
                severity: Severity::Critical,
                description: 'The Docker socket is world-readable or world-writable, which could allow container escape.',
                remediation: Remediation::create(
                    description: 'Restrict Docker socket permissions to root and docker group only.',
                    commands: ['sudo chmod 660 /var/run/docker.sock'],
                    priority: 'immediate',
                    links: ['https://docs.docker.com/engine/security/']
                )
            ));
        }
    }

    /**
     * Check for privileged containers in docker-compose files.
     */
    protected function checkPrivilegedContainers(): void
    {
        $composeFiles = [
            base_path('docker-compose.yml'),
            base_path('docker-compose.yaml'),
            base_path('docker-compose.prod.yml'),
            base_path('docker-compose.production.yml'),
        ];

        foreach ($composeFiles as $file) {
            if (!file_exists($file)) {
                continue;
            }

            $content = file_get_contents($file);
            if ($content === false) {
                continue;
            }

            if (preg_match('/privileged:\s*true/i', $content)) {
                $this->addFinding(Finding::create(
                    source: $this->getName(),
                    package: basename($file),
                    title: 'Privileged container detected',
                    severity: Severity::High,
                    description: sprintf(
                        'File %s contains a container running in privileged mode. This grants full host access.',
                        basename($file)
                    ),
                    remediation: Remediation::create(
                        description: 'Remove privileged: true and use specific capabilities instead.',
                        manualSteps: [
                            'Remove "privileged: true" from the container definition',
                            'Add only required capabilities using "cap_add"',
                            'Consider using "security_opt" for fine-grained control',
                        ],
                        priority: 'immediate',
                        links: ['https://docs.docker.com/compose/compose-file/05-services/#privileged']
                    )
                ));
            }

            if (preg_match('/network_mode:\s*["\']?host["\']?/i', $content)) {
                $this->addFinding(Finding::create(
                    source: $this->getName(),
                    package: basename($file),
                    title: 'Host network mode detected',
                    severity: Severity::Medium,
                    description: sprintf(
                        'File %s uses host network mode, bypassing Docker network isolation.',
                        basename($file)
                    ),
                    remediation: Remediation::create(
                        description: 'Use bridge or custom networks instead of host mode.',
                        manualSteps: [
                            'Remove "network_mode: host"',
                            'Define a custom network in the compose file',
                            'Expose only required ports with "ports" directive',
                        ],
                        priority: 'standard'
                    )
                ));
            }
        }
    }

    /**
     * Check for exposed Docker API in environment.
     */
    protected function checkExposedDockerApi(): void
    {
        $dockerHost = env('DOCKER_HOST', '');

        if ($dockerHost === '' || !is_string($dockerHost)) {
            return;
        }

        if (preg_match('/tcp:\/\/0\.0\.0\.0/', $dockerHost)) {
            $this->addFinding(Finding::create(
                source: $this->getName(),
                package: 'environment',
                title: 'Docker API exposed on all interfaces',
                severity: Severity::Critical,
                description: 'DOCKER_HOST is configured to listen on 0.0.0.0, exposing the Docker API to the network.',
                remediation: Remediation::create(
                    description: 'Bind Docker API to localhost only or use TLS authentication.',
                    commands: [
                        'export DOCKER_HOST=tcp://127.0.0.1:2376',
                    ],
                    manualSteps: [
                        'Configure Docker daemon to use TLS',
                        'Set up client certificate authentication',
                        'Use a firewall to restrict access to port 2375/2376',
                    ],
                    priority: 'immediate',
                    links: [
                        'https://docs.docker.com/engine/security/protect-access/',
                        'https://docs.docker.com/engine/security/https/',
                    ]
                )
            ));
        }
    }
}
