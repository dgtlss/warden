<?php

namespace Dgtlss\Warden\Services\OutputFormatters;

use Carbon\Carbon;

class JsonFormatter
{
    /**
     * Format audit findings as JSON.
     *
     * @param array $findings
     * @param array $metadata
     * @return string
     */
    public function format(array $findings, array $metadata = []): string
    {
        $output = [
            'metadata' => array_merge([
                'timestamp' => Carbon::now()->toIso8601String(),
                'version' => $this->getWardenVersion(),
                'total_findings' => count($findings),
            ], $metadata),
            'summary' => $this->generateSummary($findings),
            'findings' => $this->formatFindings($findings),
        ];

        return json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Format audit results for specific CI/CD systems.
     *
     * @param array $findings
     * @param string $format
     * @return string
     */
    public function formatForCI(array $findings, string $format = 'generic'): string
    {
        return match($format) {
            'github' => $this->formatForGitHub($findings),
            'gitlab' => $this->formatForGitLab($findings),
            'jenkins' => $this->formatForJenkins($findings),
            default => $this->format($findings),
        };
    }

    /**
     * Generate a summary of findings by severity.
     *
     * @param array $findings
     * @return array
     */
    protected function generateSummary(array $findings): array
    {
        $summary = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'total' => count($findings),
        ];

        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            if (isset($summary[$severity])) {
                $summary[$severity]++;
            }
        }

        return $summary;
    }

    /**
     * Format individual findings.
     *
     * @param array $findings
     * @return array
     */
    protected function formatFindings(array $findings): array
    {
        return array_map(function ($finding) {
            return [
                'source' => $finding['source'] ?? 'unknown',
                'package' => $finding['package'] ?? 'unknown',
                'title' => $finding['title'] ?? 'Unknown vulnerability',
                'severity' => $finding['severity'] ?? 'low',
                'cve' => $finding['cve'] ?? null,
                'cve_url' => isset($finding['cve']) 
                    ? "https://www.cve.org/CVERecord?id={$finding['cve']}" 
                    : null,
                'affected_versions' => $finding['affected_versions'] ?? null,
                'description' => $finding['description'] ?? null,
                'remediation' => $finding['remediation'] ?? null,
            ];
        }, $findings);
    }

    /**
     * Format for GitHub Actions.
     *
     * @param array $findings
     * @return string
     */
    protected function formatForGitHub(array $findings): string
    {
        $annotations = [];
        
        foreach ($findings as $finding) {
            $level = match($finding['severity'] ?? 'low') {
                'critical', 'high' => 'error',
                'medium' => 'warning',
                default => 'notice',
            };
            
            $annotations[] = [
                'level' => $level,
                'message' => sprintf(
                    '%s: %s (Severity: %s)',
                    $finding['package'] ?? 'Unknown',
                    $finding['title'] ?? 'Unknown vulnerability',
                    $finding['severity'] ?? 'low'
                ),
                'title' => 'Security Vulnerability',
            ];
        }
        
        return json_encode([
            'annotations' => $annotations,
            'summary' => $this->generateSummary($findings),
        ], JSON_PRETTY_PRINT);
    }

    /**
     * Format for GitLab CI.
     *
     * @param array $findings
     * @return string
     */
    protected function formatForGitLab(array $findings): string
    {
        $vulnerabilities = [];
        
        foreach ($findings as $finding) {
            $vulnerabilities[] = [
                'category' => 'dependency_scanning',
                'name' => $finding['title'] ?? 'Unknown vulnerability',
                'message' => $finding['description'] ?? $finding['title'] ?? 'Unknown vulnerability',
                'severity' => ucfirst($finding['severity'] ?? 'low'),
                'confidence' => 'High',
                'scanner' => [
                    'id' => 'warden',
                    'name' => 'Warden Security Scanner',
                ],
                'location' => [
                    'dependency' => [
                        'package' => [
                            'name' => $finding['package'] ?? 'unknown',
                        ],
                        'version' => $finding['affected_versions'] ?? 'unknown',
                    ],
                ],
                'identifiers' => array_filter([
                    isset($finding['cve']) ? [
                        'type' => 'cve',
                        'name' => $finding['cve'],
                        'value' => $finding['cve'],
                        'url' => "https://www.cve.org/CVERecord?id={$finding['cve']}",
                    ] : null,
                ]),
            ];
        }
        
        return json_encode([
            'version' => '14.0.0',
            'vulnerabilities' => $vulnerabilities,
        ], JSON_PRETTY_PRINT);
    }

    /**
     * Format for Jenkins.
     *
     * @param array $findings
     * @return string
     */
    protected function formatForJenkins(array $findings): string
    {
        $issues = [];
        
        foreach ($findings as $finding) {
            $priority = match($finding['severity'] ?? 'low') {
                'critical' => 'HIGHEST',
                'high' => 'HIGH',
                'medium' => 'NORMAL',
                'low' => 'LOW',
                default => 'LOW',
            };
            
            $issues[] = [
                'fileName' => 'composer.json', // Or npm package.json based on source
                'severity' => $priority,
                'message' => sprintf(
                    '%s: %s',
                    $finding['package'] ?? 'Unknown',
                    $finding['title'] ?? 'Unknown vulnerability'
                ),
                'category' => $finding['source'] ?? 'Security',
                'type' => 'Vulnerability',
                'description' => $finding['description'] ?? null,
            ];
        }
        
        return json_encode([
            'issues' => $issues,
            '_class' => 'io.jenkins.plugins.analysis.core.restapi.ReportApi',
        ], JSON_PRETTY_PRINT);
    }

    /**
     * Get current Warden version.
     *
     * @return string
     */
    protected function getWardenVersion(): string
    {
        $composerJson = json_decode(
            file_get_contents(__DIR__ . '/../../../composer.json'),
            true
        );
        
        return $composerJson['version'] ?? 'unknown';
    }
} 