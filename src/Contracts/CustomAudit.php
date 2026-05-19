<?php

namespace Dgtlss\Warden\Contracts;

interface CustomAudit
{
    /**
     * Run the custom audit.
     *
     * @return bool True if audit passed, false if issues found
     */
    public function audit(): bool;

    /**
     * Get the findings from the audit.
     *
     * @return array Array of findings with structure:
     *               [
     *                   'rule_id' => 'custom.rule-id', // optional, generated when omitted
     *                   'category' => 'security|dependency|laravel|ci|container|...', // optional
     *                   'severity' => 'critical|high|medium|low',
     *                   'title' => 'Issue title',
     *                   'description' => 'Detailed description', // optional, defaults to title
     *                   'package' => 'package-name',
     *                   'file' => 'config/app.php', // optional
     *                   'line' => 10, // optional
     *                   'remediation' => 'Suggested remediation', // optional
     *                   'references' => [
     *                       ['label' => 'Advisory', 'url' => 'https://example.test/advisory'],
     *                   ], // optional
     *                   'cve' => 'CVE-2023-XXXXX', // optional
     *                   'affected_versions' => '< 2.0', // optional
     *                   // Additional keys are preserved as metadata
     *               ]
     */
    public function getFindings(): array;

    /**
     * Get the name of this audit.
     */
    public function getName(): string;

    /**
     * Get the description of what this audit checks.
     */
    public function getDescription(): string;

    /**
     * Determine if this audit should be run.
     */
    public function shouldRun(): bool;
} 
