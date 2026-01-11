<?php

namespace Dgtlss\Warden\Services\OutputFormatters;

use Dgtlss\Warden\ValueObjects\Finding;
use Carbon\Carbon;

class JsonFormatter
{
    /**
     * Format audit findings as JSON.
     *
     * @param array<int, Finding> $findings
     * @param array<string, mixed> $metadata
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

        $jsonOutput = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        return $jsonOutput ?: '';
    }

    /**
     * Format audit results for specific CI/CD systems.
     *
     * @param array<int, Finding> $findings
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
     * @param array<int, Finding> $findings
     * @return array<string, int>
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
            $severity = $finding->severity->value;
            if ($severity === 'moderate') {
                $severity = 'medium';
            }
            if (isset($summary[$severity])) {
                $summary[$severity]++;
            }
        }

        return $summary;
    }

    /**
     * Format individual findings.
     *
     * @param array<int, Finding> $findings
     * @return array<int, array<string, mixed>>
     */
    protected function formatFindings(array $findings): array
    {
        return array_map(function (Finding $finding) {
            return array_merge($finding->toArray(), [
                'cve_url' => $finding->cve 
                    ? 'https://www.cve.org/CVERecord?id=' . $finding->cve 
                    : null,
            ]);
        }, $findings);
    }

    /**
     * Format for GitHub Actions.
     *
     * @param array<int, Finding> $findings
     */
    protected function formatForGitHub(array $findings): string
    {
        $annotations = [];
        
        foreach ($findings as $finding) {
            $level = $finding->severity->toGitHubLevel();
            
            $annotations[] = [
                'level' => $level,
                'message' => sprintf(
                    '%s: %s (Severity: %s)',
                    $finding->package,
                    $finding->title,
                    $finding->severity->value
                ),
                'title' => 'Security Vulnerability',
            ];
        }
        
        $jsonOutput = json_encode([
            'annotations' => $annotations,
            'summary' => $this->generateSummary($findings),
        ], JSON_PRETTY_PRINT);
        return $jsonOutput ?: '';
    }

    /**
     * Format for GitLab CI.
     *
     * @param array<int, Finding> $findings
     */
    protected function formatForGitLab(array $findings): string
    {
        $vulnerabilities = [];
        
        foreach ($findings as $finding) {
            $vulnerabilities[] = [
                'category' => 'dependency_scanning',
                'name' => $finding->title,
                'message' => $finding->title . ' security vulnerability found',
                'severity' => ucfirst($finding->severity->value),
                'confidence' => 'High',
                'scanner' => [
                    'id' => 'warden',
                    'name' => 'Warden Security Scanner',
                ],
                'location' => [
                    'dependency' => [
                        'package' => [
                            'name' => $finding->package,
                        ],
                        'version' => $finding->affectedVersions ?? 'unknown',
                    ],
                ],
                'identifiers' => array_filter([
                    $finding->cve ? [
                        'type' => 'cve',
                        'name' => $finding->cve,
                        'value' => $finding->cve,
                        'url' => 'https://www.cve.org/CVERecord?id=' . $finding->cve,
                    ] : null,
                ]),
            ];
        }
        
        $jsonOutput = json_encode([
            'version' => '14.0.0',
            'vulnerabilities' => $vulnerabilities,
        ], JSON_PRETTY_PRINT);
        
        return $jsonOutput ?: '';
    }

    /**
     * Format for Jenkins.
     *
     * @param array<int, Finding> $findings
     */
    protected function formatForJenkins(array $findings): string
    {
        $issues = [];
        
        foreach ($findings as $finding) {
            $priority = match($finding->severity->value) {
                'critical' => 'HIGHEST',
                'high' => 'HIGH',
                'medium', 'moderate' => 'NORMAL',
                'low' => 'LOW',
                default => 'LOW',
            };
            
            $issues[] = [
                'fileName' => 'composer.json', // Or npm package.json based on source
                'severity' => $priority,
                'message' => sprintf(
                    '%s: %s',
                    $finding->package,
                    $finding->title
                ),
                'category' => $finding->source,
                'type' => 'Vulnerability',
                'description' => $finding->title,
            ];
        }
        
        $jsonOutput = json_encode([
            'issues' => $issues,
            '_class' => 'io.jenkins.plugins.analysis.core.restapi.ReportApi',
        ], JSON_PRETTY_PRINT);
        return $jsonOutput ?: '';
    }

    /**
     * Get the current Warden version.
     */
    protected function getWardenVersion(): string
    {
        $composerPath = __DIR__ . '/../../../composer.json';
        if (!file_exists($composerPath)) {
            return 'unknown (composer.json not found)';
        }

        $composerJsonContent = file_get_contents($composerPath);
        if ($composerJsonContent === false) {
            return 'unknown (failed to read composer.json)';
        }

        $composerJson = json_decode($composerJsonContent, true);
        if (!is_array($composerJson) || !isset($composerJson['version']) || !is_string($composerJson['version'])) {
            return 'unknown (failed to parse composer.json)';
        }

        return $composerJson['version'];
    }
} 
