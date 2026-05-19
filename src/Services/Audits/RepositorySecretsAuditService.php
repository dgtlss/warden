<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Services\Audits\Concerns\ScansTextFiles;

class RepositorySecretsAuditService extends AbstractAuditService
{
    use ScansTextFiles;

    /**
     * @var array<int, array{rule_id: string, title: string, severity: string, description: string, patterns: array<int, string>, regex: string}>
     */
    private array $rules = [
        [
            'rule_id' => 'secrets.repository.literal-secret',
            'title' => 'Potential committed secret detected',
            'severity' => 'high',
            'description' => 'Repository files appear to contain a non-placeholder credential or token value.',
            'patterns' => [
                '.env.example',
                '.env.*.example',
                'config/*.php',
                'docker-compose.yml',
                'docker-compose.yaml',
                '.github/workflows/*.yml',
                '.github/workflows/*.yaml',
            ],
            'regex' => '/(secret|token|password|passwd|api[_-]?key)\s*[:=]\s*[\'"]?(?!null|false|true|changeme|example|your-|test|dummy|placeholder|\$\{)[A-Za-z0-9_\-\/\+=]{8,}[\'"]?/i',
        ],
        [
            'rule_id' => 'secrets.repository.aws-key',
            'title' => 'Potential AWS access key detected',
            'severity' => 'critical',
            'description' => 'A string matching an AWS access key identifier was found in a tracked configuration file.',
            'patterns' => [
                '.env.example',
                '.env.*.example',
                'config/*.php',
                'docker-compose.yml',
                'docker-compose.yaml',
                '.github/workflows/*.yml',
                '.github/workflows/*.yaml',
            ],
            'regex' => '/AKIA[0-9A-Z]{16}/',
        ],
    ];

    public function getName(): string
    {
        return 'repository-secrets';
    }

    public function run(): bool
    {
        foreach ($this->rules as $rule) {
            foreach ($this->matchingFiles($rule['patterns']) as $path) {
                $file = $this->readFile($path);
                if ($file === null) {
                    continue;
                }

                if (!preg_match($rule['regex'], $file['content'], $matches)) {
                    continue;
                }

                $match = (string) ($matches[0] ?? '');
                $this->addFinding([
                    'package' => 'repository',
                    'title' => $rule['title'],
                    'rule_id' => $rule['rule_id'],
                    'category' => 'secrets',
                    'severity' => $rule['severity'],
                    'description' => $rule['description'],
                    'file' => $file['relative'],
                    'line' => $this->lineNumberForSnippet($file['content'], $match),
                    'remediation' => 'Replace committed literal secrets with environment variables or placeholders before merging.',
                ]);
            }
        }

        return true;
    }
}
