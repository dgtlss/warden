<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Services\Audits\Concerns\ScansTextFiles;

class DockerSecurityAuditService extends AbstractAuditService
{
    use ScansTextFiles;

    public function getName(): string
    {
        return 'docker-security';
    }

    public function run(): bool
    {
        foreach ($this->matchingFiles(['Dockerfile', 'Dockerfile.*', 'docker-compose.yml', 'docker-compose.yaml']) as $path) {
            $file = $this->readFile($path);
            if ($file === null) {
                continue;
            }

            $content = $file['content'];
            $relative = $file['relative'];

            $this->checkCopiedSecrets($relative, $content);
            $this->checkWorldWritable($relative, $content);
            $this->checkRootUser($relative, $content);
            $this->checkDevInstall($relative, $content);
        }

        return true;
    }

    private function checkCopiedSecrets(string $file, string $content): void
    {
        foreach (['COPY .env', 'ADD .env'] as $snippet) {
            if (!str_contains($content, $snippet)) {
                continue;
            }

            $this->addFinding([
                'package' => 'docker',
                'title' => 'Docker configuration copies .env into the image',
                'rule_id' => 'docker.secrets.env-copied',
                'category' => 'container',
                'severity' => 'critical',
                'description' => 'Baking .env files into container images makes secrets difficult to rotate and easy to leak.',
                'file' => $file,
                'line' => $this->lineNumberForSnippet($content, $snippet),
                'remediation' => 'Inject secrets at runtime through environment variables or a secret manager instead of copying .env into the image.',
            ]);
        }
    }

    private function checkWorldWritable(string $file, string $content): void
    {
        foreach (['chmod 777', 'chmod -R 777'] as $snippet) {
            if (!str_contains($content, $snippet)) {
                continue;
            }

            $this->addFinding([
                'package' => 'docker',
                'title' => 'Docker configuration grants world-writable permissions',
                'rule_id' => 'docker.permissions.world-writable',
                'category' => 'container',
                'severity' => 'high',
                'description' => 'World-writable permissions in build or runtime images increase tampering risk and often mask ownership problems.',
                'file' => $file,
                'line' => $this->lineNumberForSnippet($content, $snippet),
                'remediation' => 'Use the minimum required file permissions and set ownership explicitly instead of chmod 777.',
            ]);
        }
    }

    private function checkRootUser(string $file, string $content): void
    {
        if (str_contains($content, 'USER root')) {
            $this->addFinding([
                'package' => 'docker',
                'title' => 'Container explicitly runs as root',
                'rule_id' => 'docker.runtime.user-root',
                'category' => 'container',
                'severity' => 'medium',
                'description' => 'Running the application container as root increases the impact of a compromise.',
                'file' => $file,
                'line' => $this->lineNumberForSnippet($content, 'USER root'),
                'remediation' => 'Create and use a dedicated non-root runtime user for the final image stage.',
            ]);
        }
    }

    private function checkDevInstall(string $file, string $content): void
    {
        foreach (['composer install', 'npm install'] as $snippet) {
            if (!str_contains($content, $snippet)) {
                continue;
            }

            if ($snippet === 'composer install' && str_contains($content, '--no-dev')) {
                continue;
            }

            if ($snippet === 'npm install' && (str_contains($content, '--omit=dev') || str_contains($content, 'npm ci --omit=dev'))) {
                continue;
            }

            $this->addFinding([
                'package' => 'docker',
                'title' => 'Container build installs dependencies without excluding development packages',
                'rule_id' => 'docker.dependencies.dev-installed',
                'category' => 'container',
                'severity' => 'medium',
                'description' => 'Production container builds should minimize attack surface by excluding development dependencies.',
                'file' => $file,
                'line' => $this->lineNumberForSnippet($content, $snippet),
                'remediation' => 'Use production-focused install flags such as composer install --no-dev or npm ci --omit=dev in final images.',
            ]);
        }
    }
}
