<?php

namespace Dgtlss\Warden\Services;

use Carbon\Carbon;
use Dgtlss\Warden\Data\AuditRunReport;

class ReportFormatter
{
    public function __construct()
    {
    }

    /**
     * @return array<string, mixed>
     */
    public function json(AuditRunReport $report): array
    {
        return [
            'warden_version' => $this->wardenVersion(),
            'scan_date' => Carbon::now()->toISOString(),
            'profile' => $report->profile,
            'vulnerabilities_found' => count($report->findings),
            'suppressed_findings' => count($report->suppressedFindings),
            'findings' => $report->findings,
            'metadata' => $report->metadata,
        ];
    }

    /**
     * @return array<int, string>
     */
    public function github(AuditRunReport $report): array
    {
        if ($report->findings === []) {
            return ['::notice title=Warden Security Audit::No security issues found.'];
        }

        $lines = [];

        foreach ($report->findings as $finding) {
            $level = in_array($finding['severity'] ?? 'low', ['critical', 'high'], true) ? 'error' : 'warning';
            $title = $this->escapeGitHubWorkflowKeyValue((string) ($finding['title'] ?? 'Security vulnerability'));
            $message = $this->escapeGitHubWorkflowMessage(sprintf(
                '%s - %s severity vulnerability found',
                (string) ($finding['package'] ?? 'unknown'),
                (string) ($finding['severity'] ?? 'unknown')
            ));

            $location = [];
            if (isset($finding['file']) && is_string($finding['file']) && $finding['file'] !== '') {
                $location[] = 'file=' . $this->escapeGitHubWorkflowKeyValue($finding['file']);
            }

            if (isset($finding['line']) && is_numeric($finding['line'])) {
                $location[] = 'line=' . (int) $finding['line'];
            }

            $prefix = $location === [] ? '' : implode(',', $location) . ',';
            $lines[] = sprintf('::%s %stitle=%s::%s', $level, $prefix, $title, $message);
        }

        return $lines;
    }

    /**
     * @return array<string, mixed>
     */
    public function gitlab(AuditRunReport $report): array
    {
        $vulnerabilities = [];

        foreach ($report->findings as $finding) {
            $locationFile = (string) ($finding['file'] ?? 'composer.json');
            $vulnerabilities[] = [
                'id' => hash('sha256', serialize($finding)),
                'category' => 'dependency_scanning',
                'name' => $finding['title'] ?? 'Security vulnerability',
                'description' => $finding['description'] ?? $finding['title'] ?? 'Security vulnerability found',
                'severity' => strtoupper((string) ($finding['severity'] ?? 'Medium')),
                'scanner' => [
                    'id' => 'warden',
                    'name' => 'Warden',
                ],
                'location' => [
                    'file' => $locationFile,
                    'dependency' => [
                        'package' => [
                            'name' => $finding['package'] ?? 'unknown',
                        ],
                    ],
                ],
            ];
        }

        return [
            'version' => '15.0.0',
            'vulnerabilities' => $vulnerabilities,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jenkins(AuditRunReport $report): array
    {
        return [
            'warden_report' => [
                'timestamp' => Carbon::now()->toISOString(),
                'total_vulnerabilities' => count($report->findings),
                'profile' => $report->profile,
                'vulnerabilities' => $report->findings,
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function sarif(AuditRunReport $report): array
    {
        $rules = [];
        $results = [];

        foreach ($report->findings as $finding) {
            $ruleId = (string) $finding['rule_id'];

            if (!isset($rules[$ruleId])) {
                $rules[$ruleId] = [
                    'id' => $ruleId,
                    'shortDescription' => [
                        'text' => (string) ($finding['title'] ?? $ruleId),
                    ],
                    'fullDescription' => [
                        'text' => (string) ($finding['description'] ?? $finding['title'] ?? $ruleId),
                    ],
                    'help' => [
                        'text' => (string) ($finding['remediation'] ?? 'Review and remediate this finding.'),
                    ],
                    'properties' => [
                        'tags' => [
                            'warden',
                            (string) ($finding['category'] ?? 'security'),
                            (string) ($finding['severity'] ?? 'low'),
                        ],
                    ],
                ];
            }

            $result = [
                'ruleId' => $ruleId,
                'level' => $this->sarifLevel((string) ($finding['severity'] ?? 'low')),
                'message' => [
                    'text' => (string) ($finding['title'] ?? $ruleId),
                ],
                'partialFingerprints' => [
                    'primaryLocationLineHash' => (string) ($finding['fingerprint'] ?? hash('sha256', serialize($finding))),
                ],
                'properties' => [
                    'package' => $finding['package'] ?? null,
                    'source' => $finding['source'] ?? null,
                    'severity' => $finding['severity'] ?? null,
                ],
            ];

            if (isset($finding['file']) && is_string($finding['file']) && $finding['file'] !== '') {
                $result['locations'] = [[
                    'physicalLocation' => [
                        'artifactLocation' => [
                            'uri' => $finding['file'],
                        ],
                        'region' => [
                            'startLine' => (int) ($finding['line'] ?? 1),
                        ],
                    ],
                ]];
            }

            $results[] = $result;
        }

        return [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'Warden',
                        'version' => $this->wardenVersion(),
                        'informationUri' => 'https://github.com/dgtlss/warden',
                        'rules' => array_values($rules),
                    ],
                ],
                'automationDetails' => [
                    'id' => 'warden/' . $report->profile,
                ],
                'results' => $results,
            ]],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function cyclonedx(AuditRunReport $report): array
    {
        $components = [];
        $vulnerabilities = [];

        foreach ($report->findings as $finding) {
            $package = (string) ($finding['package'] ?? 'unknown');
            $bomRef = 'component:' . $package;

            if (!isset($components[$bomRef])) {
                $components[$bomRef] = [
                    'type' => 'library',
                    'name' => $package,
                    'bom-ref' => $bomRef,
                ];
            }

            $references = [];
            foreach ((array) ($finding['references'] ?? []) as $reference) {
                if (!is_array($reference) || !isset($reference['url'])) {
                    continue;
                }

                $references[] = [
                    'id' => (string) ($reference['label'] ?? $reference['url']),
                    'source' => [
                        'name' => 'Warden',
                        'url' => (string) $reference['url'],
                    ],
                ];
            }

            $vulnerabilities[] = [
                'id' => (string) ($finding['rule_id'] ?? hash('sha256', serialize($finding))),
                'source' => [
                    'name' => 'Warden',
                ],
                'ratings' => [[
                    'severity' => strtolower((string) ($finding['severity'] ?? 'low')),
                ]],
                'description' => (string) ($finding['description'] ?? $finding['title'] ?? 'Security issue'),
                'affects' => [[
                    'ref' => $bomRef,
                ]],
                'advisories' => $references,
            ];
        }

        return [
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.5',
            'serialNumber' => 'urn:uuid:' . $this->reportUuid($report),
            'version' => 1,
            'metadata' => [
                'timestamp' => Carbon::now()->toISOString(),
                'tools' => [[
                    'vendor' => 'dgtlss',
                    'name' => 'Warden',
                    'version' => $this->wardenVersion(),
                ]],
                'component' => [
                    'type' => 'application',
                    'name' => config('warden.app_name', 'Application'),
                ],
            ],
            'components' => array_values($components),
            'vulnerabilities' => $vulnerabilities,
        ];
    }

    public function markdown(AuditRunReport $report): string
    {
        $lines = [
            '# Warden Security Report',
            '',
            '- Profile: `' . $report->profile . '`',
            '- Generated: `' . Carbon::now()->toIso8601String() . '`',
            '- Findings: `' . count($report->findings) . '`',
            '- Suppressed: `' . count($report->suppressedFindings) . '`',
            '',
        ];

        if ($report->findings === []) {
            $lines[] = 'No active security issues were found.';
            return implode(PHP_EOL, $lines);
        }

        $lines[] = '| Severity | Source | Package | Title | File |';
        $lines[] = '| --- | --- | --- | --- | --- |';

        foreach ($report->findings as $finding) {
            $lines[] = sprintf(
                '| %s | %s | %s | %s | %s |',
                ucfirst((string) ($finding['severity'] ?? 'low')),
                (string) ($finding['source'] ?? 'unknown'),
                (string) ($finding['package'] ?? 'unknown'),
                str_replace('|', '\|', (string) ($finding['title'] ?? 'Security issue')),
                (string) ($finding['file'] ?? '-')
            );
        }

        return implode(PHP_EOL, $lines);
    }

    public function html(AuditRunReport $report): string
    {
        $rows = '';
        foreach ($report->findings as $finding) {
            $rows .= sprintf(
                '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
                htmlspecialchars(ucfirst((string) ($finding['severity'] ?? 'low'))),
                htmlspecialchars((string) ($finding['source'] ?? 'unknown')),
                htmlspecialchars((string) ($finding['package'] ?? 'unknown')),
                htmlspecialchars((string) ($finding['title'] ?? 'Security issue')),
                htmlspecialchars((string) ($finding['file'] ?? '-'))
            );
        }

        if ($rows === '') {
            $rows = '<tr><td colspan="5">No active security issues were found.</td></tr>';
        }

        return sprintf(
            '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Warden Security Report</title><style>body{font-family:Arial,sans-serif;padding:24px;color:#1f2937}table{width:100%%;border-collapse:collapse;margin-top:24px}th,td{border:1px solid #d1d5db;padding:10px;text-align:left}th{background:#111827;color:#fff}h1{margin-bottom:8px}.meta{color:#4b5563}</style></head><body><h1>Warden Security Report</h1><p class="meta">Profile: %s<br>Generated: %s<br>Findings: %d<br>Suppressed: %d</p><table><thead><tr><th>Severity</th><th>Source</th><th>Package</th><th>Title</th><th>File</th></tr></thead><tbody>%s</tbody></table></body></html>',
            htmlspecialchars($report->profile),
            htmlspecialchars(Carbon::now()->toIso8601String()),
            count($report->findings),
            count($report->suppressedFindings),
            $rows
        );
    }

    protected function escapeGitHubWorkflowKeyValue(string $value): string
    {
        return str_replace(['%', "\r", "\n", ':', ','], ['%25', '%0D', '%0A', '%3A', '%2C'], $value);
    }

    protected function escapeGitHubWorkflowMessage(string $value): string
    {
        return str_replace(['%', "\r", "\n"], ['%25', '%0D', '%0A'], $value);
    }

    protected function sarifLevel(string $severity): string
    {
        return match ($severity) {
            'critical', 'high' => 'error',
            'medium' => 'warning',
            default => 'note',
        };
    }

    protected function reportUuid(AuditRunReport $report): string
    {
        $seed = hash('sha256', json_encode([
            'profile' => $report->profile,
            'generated_at' => Carbon::now()->toISOString(),
            'count' => count($report->findings),
        ], JSON_UNESCAPED_SLASHES));

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($seed, 0, 8),
            substr($seed, 8, 4),
            substr($seed, 12, 4),
            substr($seed, 16, 4),
            substr($seed, 20, 12)
        );
    }

    protected function wardenVersion(): string
    {
        $composerPath = dirname(__DIR__, 2) . '/composer.json';
        $contents = file_get_contents($composerPath);
        $decoded = $contents !== false ? json_decode($contents, true) : null;

        return is_array($decoded) && isset($decoded['version']) && is_string($decoded['version'])
            ? $decoded['version']
            : 'unknown';
    }
}
