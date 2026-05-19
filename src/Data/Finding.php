<?php

namespace Dgtlss\Warden\Data;

class Finding
{
    /**
     * @param array<int, array<string, string>> $references
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public readonly string $ruleId,
        public readonly string $category,
        public readonly string $severity,
        public readonly string $title,
        public readonly string $description,
        public readonly ?string $file,
        public readonly ?int $line,
        public readonly string $fingerprint,
        public readonly ?string $remediation,
        public readonly array $references,
        public readonly string $package,
        public readonly string $source,
        public readonly array $metadata = [],
    ) {
    }

    /**
     * @param array<string, mixed> $finding
     */
    public static function fromArray(array $finding, string $source, string $auditId): self
    {
        $category = (string) ($finding['category'] ?? 'security');
        $package = (string) ($finding['package'] ?? $source);
        $title = (string) ($finding['title'] ?? 'Security issue');
        $description = (string) ($finding['description'] ?? $title);
        $severity = strtolower((string) ($finding['severity'] ?? 'low'));
        $file = self::normalizeFile($finding['file'] ?? null);
        $line = self::normalizeLine($finding['line'] ?? null);
        $remediation = isset($finding['remediation']) ? (string) $finding['remediation'] : null;
        $references = self::normalizeReferences($finding);
        $ruleId = self::normalizeRuleId($finding['rule_id'] ?? null, $auditId, $category, $package, $title);

        $metadata = $finding;
        unset(
            $metadata['rule_id'],
            $metadata['category'],
            $metadata['severity'],
            $metadata['title'],
            $metadata['description'],
            $metadata['file'],
            $metadata['line'],
            $metadata['fingerprint'],
            $metadata['remediation'],
            $metadata['references'],
            $metadata['package'],
            $metadata['source']
        );

        $fingerprint = (string) ($finding['fingerprint'] ?? self::buildFingerprint(
            auditId: $auditId,
            ruleId: $ruleId,
            package: $package,
            title: $title,
            file: $file,
            line: $line,
            severity: $severity
        ));

        return new self(
            ruleId: $ruleId,
            category: $category,
            severity: $severity,
            title: $title,
            description: $description,
            file: $file,
            line: $line,
            fingerprint: $fingerprint,
            remediation: $remediation,
            references: $references,
            package: $package,
            source: $source,
            metadata: $metadata,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $payload = [
            'rule_id' => $this->ruleId,
            'category' => $this->category,
            'severity' => $this->severity,
            'title' => $this->title,
            'description' => $this->description,
            'file' => $this->file,
            'line' => $this->line,
            'fingerprint' => $this->fingerprint,
            'remediation' => $this->remediation,
            'references' => $this->references,
            'package' => $this->package,
            'source' => $this->source,
        ];

        if (isset($this->metadata['cve']) && is_string($this->metadata['cve'])) {
            $payload['cve'] = $this->metadata['cve'];
        }

        if (isset($this->metadata['affected_versions']) && is_string($this->metadata['affected_versions'])) {
            $payload['affected_versions'] = $this->metadata['affected_versions'];
        }

        if (isset($this->metadata['error']) && is_string($this->metadata['error'])) {
            $payload['error'] = $this->metadata['error'];
        }

        foreach ($this->metadata as $key => $value) {
            if (!array_key_exists($key, $payload)) {
                $payload[$key] = $value;
            }
        }

        return $payload;
    }

    private static function normalizeRuleId(?string $ruleId, string $auditId, string $category, string $package, string $title): string
    {
        if (is_string($ruleId) && $ruleId !== '') {
            return $ruleId;
        }

        $segments = [
            trim($auditId),
            trim($category),
            trim($package),
            trim($title),
        ];

        $normalized = array_map(
            static fn (string $segment): string => strtolower(
                trim((string) preg_replace('/[^a-zA-Z0-9]+/', '-', $segment), '-')
            ),
            array_filter($segments, static fn (string $segment): bool => $segment !== '')
        );

        return implode('.', $normalized);
    }

    private static function normalizeFile(mixed $file): ?string
    {
        if (!is_string($file) || $file === '') {
            return null;
        }

        $normalized = str_replace('\\', '/', $file);
        $basePath = str_replace('\\', '/', base_path()) . '/';

        if (str_starts_with($normalized, $basePath)) {
            return substr($normalized, strlen($basePath));
        }

        return ltrim($normalized, './');
    }

    private static function normalizeLine(mixed $line): ?int
    {
        if (is_int($line) && $line > 0) {
            return $line;
        }

        if (is_numeric($line) && (int) $line > 0) {
            return (int) $line;
        }

        return null;
    }

    /**
     * @param array<string, mixed> $finding
     * @return array<int, array<string, string>>
     */
    private static function normalizeReferences(array $finding): array
    {
        $references = [];

        if (isset($finding['references']) && is_array($finding['references'])) {
            foreach ($finding['references'] as $reference) {
                if (!is_array($reference)) {
                    continue;
                }

                $url = isset($reference['url']) && is_string($reference['url']) ? $reference['url'] : null;
                if ($url === null || $url === '') {
                    continue;
                }

                $references[] = [
                    'label' => isset($reference['label']) && is_string($reference['label']) ? $reference['label'] : $url,
                    'url' => $url,
                ];
            }
        }

        if (isset($finding['cve']) && is_string($finding['cve']) && $finding['cve'] !== '') {
            $value = $finding['cve'];
            $url = str_starts_with($value, 'http') ? $value : 'https://www.cve.org/CVERecord?id=' . $value;
            $references[] = [
                'label' => $value,
                'url' => $url,
            ];
        }

        return $references;
    }

    private static function buildFingerprint(
        string $auditId,
        string $ruleId,
        string $package,
        string $title,
        ?string $file,
        ?int $line,
        string $severity,
    ): string {
        return hash('sha256', json_encode([
            'audit' => $auditId,
            'rule' => $ruleId,
            'package' => $package,
            'title' => $title,
            'file' => $file,
            'line' => $line,
            'severity' => $severity,
        ], JSON_UNESCAPED_SLASHES));
    }
}
