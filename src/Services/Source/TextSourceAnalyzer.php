<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Source;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Services\RulePolicy;
use Dgtlss\Warden\ValueObjects\Finding;
use Symfony\Component\Finder\SplFileInfo;

final class TextSourceAnalyzer
{
    /** @var array<string, string> */
    private const SECRET_PATTERNS = [
        'AWS access key' => '/\bAKIA[0-9A-Z]{16}\b/',
        'GitHub token' => '/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_\w{20,}\b/',
        'GitLab token' => '/\bgl(?:pat|cbt|dt|rt)-[A-Za-z0-9_.-]{20,}\b/',
        'Stripe secret key' => '/\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b/',
        'Slack token' => '/\bxox[baprs]-[0-9A-Za-z-]{10,}\b/',
        'Google API key' => '/\bAIza[0-9A-Za-z_-]{35}\b/',
        'OpenAI API key' => '/\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/',
        'Anthropic API key' => '/\bsk-ant-[A-Za-z0-9_-]{20,}\b/',
        'npm token' => '/\bnpm_[A-Za-z0-9]{36,}\b/',
        'private key' => '/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/',
    ];

    public function __construct(private readonly RulePolicy $rulePolicy)
    {
    }

    /**
     * @param list<SplFileInfo> $files
     * @return list<Finding>
     */
    public function secrets(array $files): array
    {
        $findings = [];
        foreach ($files as $file) {
            $contents = $file->getContents();
            $path = $this->relativePath($file);
            foreach (explode("\n", $contents) as $index => $line) {
                foreach (self::SECRET_PATTERNS as $provider => $pattern) {
                    if (!$this->rulePolicy->enabled('source.secrets.provider-credential') || preg_match($pattern, $line, $match) !== 1) {
                        continue;
                    }

                    $findings[] = new Finding(
                        id: 'source.secrets.provider-credential',
                        source: 'source',
                        title: sprintf('%s appears to be committed in source', $provider),
                        severity: Severity::Critical,
                        description: sprintf('A provider-format credential was detected at %s:%d. Its value has been redacted.', $path, $index + 1),
                        remediation: 'Revoke and rotate the credential, remove it from history, and load it from a secret store.',
                        path: $path,
                        line: $index + 1,
                        identity: hash('sha256', $match[0]),
                    );
                    continue 2;
                }

                if (
                    $this->rulePolicy->enabled('source.secrets.suspicious-literal')
                    && preg_match('/(?:password|secret|api_?key|access_?token|private_?key)["\']?\s*(?:=>|=)\s*["\']([^"\']{8,})["\']/i', $line, $match) === 1
                    && $this->looksLikeCredential($match[1])
                ) {
                    $findings[] = new Finding(
                        id: 'source.secrets.suspicious-literal',
                        source: 'source',
                        title: 'Secret-like value is assigned as a literal',
                        severity: Severity::Medium,
                        description: sprintf('A secret-named value is assigned a literal at %s:%d. The value has been redacted.', $path, $index + 1),
                        remediation: 'Confirm the value is fake or move it to a deployment secret store.',
                        path: $path,
                        line: $index + 1,
                        blocking: false,
                        identity: hash('sha256', $match[1]),
                    );
                }
            }
        }

        return $findings;
    }

    private function looksLikeCredential(string $value): bool
    {
        // Values with spaces or other symbols found in validation are likely not credentials
        if (preg_match('/[\s|{}<>]/', $value) === 1) {
            return false;
        }

        // Values not containing digits or symbols are likely not credentials
        return preg_match('/^[A-Za-z]+(?:[_.\-][A-Za-z]+)*$/', $value) !== 1;
    }

    /**
     * @param list<SplFileInfo> $files
     * @return list<Finding>
     */
    public function blade(array $files): array
    {
        $findings = [];
        foreach ($files as $file) {
            $contents = $file->getContents();
            $path = $this->relativePath($file);
            foreach (explode("\n", $contents) as $index => $line) {
                if ($this->rulePolicy->enabled('source.blade.unescaped-output') && preg_match('/\{!!\s*\$(?!slot\b|attributes\b)([^!]+)!!\}/', $line, $match) === 1) {
                    $findings[] = $this->advisory('source.blade.unescaped-output', 'Blade renders unescaped output', Severity::Medium, 'Unescaped Blade output may render attacker-controlled HTML.', 'Use escaped {{ }} output or sanitize trusted HTML explicitly.', $path, $index + 1, trim($match[1]));
                }
            }

            if ($this->rulePolicy->enabled('source.blade.form-missing-csrf') && preg_match_all('/<form\b[^>]*method=["\'](?:post|put|patch|delete)["\'][^>]*>(.*?)<\/form>/is', $contents, $forms, PREG_OFFSET_CAPTURE) > 0) {
                foreach ($forms[0] as [$form, $offset]) {
                    if (str_contains(strtolower($form), 'wire:submit') || preg_match('/@csrf|csrf_field\s*\(|csrf_token\s*\(/i', $form) === 1) {
                        continue;
                    }

                    $line = substr_count(substr($contents, 0, $offset), "\n") + 1;
                    $findings[] = $this->advisory('source.blade.form-missing-csrf', 'Mutable Blade form has no CSRF directive', Severity::Medium, 'A non-Livewire mutable form does not contain an obvious CSRF token.', 'Add @csrf inside the form or document the alternative protection.', $path, $line, 'form:' . $line);
                }
            }
        }

        return $findings;
    }

    private function advisory(string $id, string $title, Severity $severity, string $description, string $remediation, string $path, int $line, string $identity): Finding
    {
        return new Finding($id, 'source', $title, $severity, $description, $remediation, path: $path, line: $line, blocking: false, identity: $identity);
    }

    private function relativePath(SplFileInfo $file): string
    {
        return ltrim(str_replace(base_path(), '', $file->getRealPath()), DIRECTORY_SEPARATOR);
    }
}
