<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Services\Audits\Concerns\ScansTextFiles;

class CiWorkflowAuditService extends AbstractAuditService
{
    use ScansTextFiles;

    public function getName(): string
    {
        return 'ci-workflow';
    }

    public function run(): bool
    {
        foreach ($this->matchingFiles(['.github/workflows/*.yml', '.github/workflows/*.yaml']) as $path) {
            $file = $this->readFile($path);
            if ($file === null) {
                continue;
            }

            $content = $file['content'];

            $this->checkPullRequestTarget($file['relative'], $content);
            $this->checkWriteAllPermissions($file['relative'], $content);
            $this->checkUnpinnedActions($file['relative'], $content);
            $this->checkUnsafeSecretsInheritance($file['relative'], $content);
            $this->checkShellInterpolation($file['relative'], $content);
        }

        return true;
    }

    private function checkPullRequestTarget(string $file, string $content): void
    {
        if (!str_contains($content, 'pull_request_target')) {
            return;
        }

        $this->addFinding([
            'package' => 'github-actions',
            'title' => 'Workflow uses pull_request_target',
            'rule_id' => 'ci.workflow.pull-request-target',
            'category' => 'ci',
            'severity' => 'high',
            'description' => 'pull_request_target workflows run with elevated permissions and should be reviewed carefully for untrusted PR execution.',
            'file' => $file,
            'line' => $this->lineNumberForSnippet($content, 'pull_request_target'),
            'remediation' => 'Prefer pull_request where possible, or strictly isolate any pull_request_target workflow steps.',
        ]);
    }

    private function checkWriteAllPermissions(string $file, string $content): void
    {
        if (!str_contains($content, 'write-all')) {
            return;
        }

        $this->addFinding([
            'package' => 'github-actions',
            'title' => 'Workflow grants write-all permissions',
            'rule_id' => 'ci.workflow.permissions.write-all',
            'category' => 'ci',
            'severity' => 'high',
            'description' => 'GitHub Actions workflows should request the minimum permissions required instead of write-all.',
            'file' => $file,
            'line' => $this->lineNumberForSnippet($content, 'write-all'),
            'remediation' => 'Replace write-all with explicit least-privilege permissions for the job or workflow.',
        ]);
    }

    private function checkUnpinnedActions(string $file, string $content): void
    {
        $lines = preg_split('/\R/', $content) ?: [];

        foreach ($lines as $index => $line) {
            if (!preg_match('/uses:\s*([^@\s]+)@([^\s]+)/', $line, $matches)) {
                continue;
            }

            $action = (string) $matches[1];
            $ref = (string) $matches[2];

            if (str_starts_with($action, './') || preg_match('/^[a-f0-9]{40}$/i', $ref)) {
                continue;
            }

            $this->addFinding([
                'package' => $action,
                'title' => 'Third-party GitHub Action is not pinned to a commit SHA',
                'rule_id' => 'ci.workflow.action.not-pinned',
                'category' => 'ci',
                'severity' => 'medium',
                'description' => 'Tag-based action references can change over time and increase supply-chain risk.',
                'file' => $file,
                'line' => $index + 1,
                'remediation' => 'Pin third-party actions to a full commit SHA, then update them intentionally.',
            ]);
        }
    }

    private function checkUnsafeSecretsInheritance(string $file, string $content): void
    {
        if (!str_contains($content, 'secrets: inherit')) {
            return;
        }

        $this->addFinding([
            'package' => 'github-actions',
            'title' => 'Workflow inherits all secrets',
            'rule_id' => 'ci.workflow.secrets.inherit',
            'category' => 'ci',
            'severity' => 'medium',
            'description' => 'Inheriting all secrets into reusable workflows widens the blast radius of a compromised job.',
            'file' => $file,
            'line' => $this->lineNumberForSnippet($content, 'secrets: inherit'),
            'remediation' => 'Pass only the specific secrets required by the called workflow.',
        ]);
    }

    private function checkShellInterpolation(string $file, string $content): void
    {
        $lines = preg_split('/\R/', $content) ?: [];

        foreach ($lines as $index => $line) {
            if (!str_contains($line, '${{')) {
                continue;
            }

            if (!preg_match('/github\.event\.(pull_request|issue|comment|head_commit)/', $line)) {
                continue;
            }

            if (!preg_match('/\|\s*(sh|bash|zsh)\b/', $line) && !preg_match('/run:\s*.*\$\{\{.*\}\}.*/', $line)) {
                continue;
            }

            $this->addFinding([
                'package' => 'github-actions',
                'title' => 'Workflow interpolates untrusted event data into shell execution',
                'rule_id' => 'ci.workflow.shell-interpolation',
                'category' => 'ci',
                'severity' => 'high',
                'description' => 'Interpolating issue, PR, or commit data into shell commands can create command-injection paths in CI.',
                'file' => $file,
                'line' => $index + 1,
                'remediation' => 'Avoid direct shell interpolation of untrusted GitHub context values; pass data as arguments or sanitize first.',
            ]);
        }
    }
}
