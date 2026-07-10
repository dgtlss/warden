<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Reporters;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\Finding;
use JsonException;

final class GitLabReporter implements ReportFormatter
{
    /** @throws JsonException */
    public function format(AuditReport $auditReport): string
    {
        $timestamp = ($auditReport->scannedAt ?? now())->format('Y-m-d\TH:i:s');
        $version = '2.0.0';
        $component = [
            'id' => 'warden',
            'name' => 'Warden',
            'url' => 'https://github.com/dgtlss/warden',
            'vendor' => ['name' => 'Dgtlss'],
            'version' => $version,
        ];

        $payload = [
            'version' => '15.2.4',
            'scan' => [
                'analyzer' => $component,
                'scanner' => $component,
                'type' => 'dependency_scanning',
                'start_time' => $timestamp,
                'end_time' => $timestamp,
                'status' => $auditReport->errors() === [] ? 'success' : 'failure',
                'messages' => array_map(static fn ($error): array => [
                    'level' => 'fatal',
                    'value' => sprintf('%s: %s', $error->code, $error->message),
                ], $auditReport->errors()),
            ],
            'vulnerabilities' => array_map(fn (Finding $finding): array => $this->vulnerability($finding), $auditReport->findings()),
            'dependency_files' => $this->dependencyFiles($auditReport),
        ];

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
    }

    /** @return array<string, mixed> */
    private function vulnerability(Finding $finding): array
    {
        $path = $finding->path ?? ($finding->source === 'npm' ? 'package-lock.json' : 'composer.lock');
        $identifier = $finding->reference ?? $finding->id;
        $identifierData = [
            'type' => str_contains(strtoupper($identifier), 'CVE-') ? 'cve' : 'warden',
            'name' => $identifier,
            'value' => $identifier,
        ];
        if ($finding->reference !== null) {
            $identifierData['url'] = $finding->reference;
        }

        return [
            'id' => $finding->fingerprint(),
            'category' => 'dependency_scanning',
            'name' => $finding->title,
            'description' => $finding->description,
            'severity' => ucfirst($finding->severity->value),
            'solution' => $finding->remediation ?? 'Review and remediate the finding.',
            'scanner' => ['id' => 'warden', 'name' => 'Warden'],
            'location' => [
                'file' => $path,
                'dependency' => [
                    'package' => ['name' => $finding->package ?? 'application'],
                    'version' => is_string($finding->metadata['affected_versions'] ?? null)
                        ? $finding->metadata['affected_versions']
                        : 'unknown',
                ],
            ],
            'identifiers' => [$identifierData],
            'links' => $finding->reference === null ? [] : [['url' => $finding->reference]],
        ];
    }

    /** @return list<array<string, mixed>> */
    private function dependencyFiles(AuditReport $auditReport): array
    {
        $files = [];
        foreach ($auditReport->findings() as $finding) {
            if ($finding->package === null || $finding->path === null) {
                continue;
            }

            $files[$finding->path][] = [
                'package' => ['name' => $finding->package],
                'version' => is_string($finding->metadata['affected_versions'] ?? null)
                    ? $finding->metadata['affected_versions']
                    : 'unknown',
            ];
        }

        $output = [];
        foreach ($files as $path => $dependencies) {
            $output[] = [
                'path' => $path,
                'package_manager' => $path === 'package-lock.json' ? 'npm' : 'composer',
                'dependencies' => $dependencies,
            ];
        }

        return $output;
    }
}
