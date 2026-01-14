<?php

namespace Dgtlss\Warden\Services\OutputFormatters;

use Dgtlss\Warden\ValueObjects\Finding;

/**
 * SARIF (Static Analysis Results Interchange Format) 2.1.0 formatter.
 * Compatible with GitHub Advanced Security and other SARIF consumers.
 *
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
class SarifFormatter
{
    /**
     * Format findings as SARIF 2.1.0 JSON.
     *
     * @param array<int, Finding> $findings
     */
    public function format(array $findings): string
    {
        $sarif = [
            'version' => '2.1.0',
            '$schema' => 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'Warden',
                            'informationUri' => 'https://github.com/dgtlss/warden',
                            'version' => '1.4.1',
                            'semanticVersion' => '1.4.1',
                            'rules' => $this->extractRules($findings),
                        ],
                    ],
                    'results' => $this->formatResults($findings),
                ],
            ],
        ];

        $json = json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            return '{}';
        }

        return $json;
    }

    /**
     * Extract unique rules from findings.
     *
     * @param array<int, Finding> $findings
     * @return array<int, array<string, mixed>>
     */
    protected function extractRules(array $findings): array
    {
        $rules = [];
        $seen = [];

        foreach ($findings as $finding) {
            $ruleId = $this->getRuleId($finding);

            if (isset($seen[$ruleId])) {
                continue;
            }

            $seen[$ruleId] = true;

            $rules[] = [
                'id' => $ruleId,
                'name' => $ruleId,
                'shortDescription' => [
                    'text' => $finding->title,
                ],
                'fullDescription' => [
                    'text' => $finding->error ?? $finding->title,
                ],
                'help' => [
                    'text' => $this->getHelpText($finding),
                ],
                'properties' => [
                    'tags' => ['security', 'vulnerability'],
                    'precision' => 'high',
                ],
                'defaultConfiguration' => [
                    'level' => $this->mapSeverityToLevel($finding->severity->value),
                ],
            ];
        }

        return $rules;
    }

    /**
     * Format findings as SARIF results.
     *
     * @param array<int, Finding> $findings
     * @return array<int, array<string, mixed>>
     */
    protected function formatResults(array $findings): array
    {
        $results = [];

        foreach ($findings as $finding) {
            $result = [
                'ruleId' => $this->getRuleId($finding),
                'level' => $this->mapSeverityToLevel($finding->severity->value),
                'message' => [
                    'text' => $finding->error ?? $finding->title,
                ],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => $this->getArtifactUri($finding),
                            ],
                        ],
                    ],
                ],
                'properties' => [
                    'package' => $finding->package,
                    'severity' => $finding->severity->value,
                    'cve' => $finding->cve,
                    'affected_versions' => $finding->affectedVersions,
                ],
            ];

            if ($finding->hasRemediation() && $finding->remediation !== null) {
                $result['fixes'] = $this->formatFixes($finding);
            }

            $results[] = $result;
        }

        return $results;
    }

    /**
     * Format remediation as SARIF fixes.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function formatFixes(Finding $finding): array
    {
        if (!$finding->hasRemediation() || $finding->remediation === null) {
            return [];
        }

        $remediation = $finding->remediation;
        $fixes = [];

        $description = $remediation->description;

        if ($remediation->hasCommands()) {
            $description .= "\n\nCommands:\n" . implode("\n", array_map(fn($cmd) => "  $ {$cmd}", $remediation->commands));
        }

        if ($remediation->hasManualSteps()) {
            $description .= "\n\nManual Steps:\n" . implode("\n", array_map(fn($step, $i) => "  " . ($i + 1) . ". {$step}", $remediation->manualSteps, array_keys($remediation->manualSteps)));
        }

        if ($remediation->hasLinks()) {
            $description .= "\n\nReferences:\n" . implode("\n", array_map(fn($link) => "  - {$link}", $remediation->links));
        }

        $fixes[] = [
            'description' => [
                'text' => $description,
            ],
            'artifactChanges' => [],
        ];

        return $fixes;
    }

    /**
     * Generate a rule ID from a finding.
     */
    protected function getRuleId(Finding $finding): string
    {
        // Create a stable rule ID from source and title
        $source = str_replace([' ', '/'], ['_', '_'], strtolower($finding->source));
        $title = preg_replace('/[^a-z0-9]+/', '_', strtolower($finding->title));

        if (!is_string($title)) {
            $title = 'unknown';
        }

        return "warden/{$source}/{$title}";
    }

    /**
     * Map Warden severity to SARIF level.
     */
    protected function mapSeverityToLevel(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical' => 'error',
            'high' => 'error',
            'medium', 'moderate' => 'warning',
            'low' => 'note',
            default => 'warning',
        };
    }

    /**
     * Get help text for a finding.
     */
    protected function getHelpText(Finding $finding): string
    {
        $help = $finding->error ?? $finding->title;

        if ($finding->cve) {
            $help .= "\n\nCVE: " . $finding->cve;
        }

        if ($finding->affectedVersions) {
            $help .= "\nAffected Versions: " . $finding->affectedVersions;
        }

        return $help;
    }

    /**
     * Get artifact URI for a finding.
     */
    protected function getArtifactUri(Finding $finding): string
    {
        // Map finding source to relevant file
        return match (strtolower($finding->source)) {
            'composer audit' => 'composer.json',
            'npm audit' => 'package.json',
            'env audit' => '.env',
            'storage audit' => 'storage/',
            'debug mode' => 'config/app.php',
            'config' => 'config/',
            'security headers' => 'config/app.php',
            'database security' => 'config/database.php',
            'cors configuration' => 'config/cors.php',
            'ssl/tls configuration' => 'config/session.php',
            'file permissions' => '.',
            default => 'package.json',
        };
    }
}
