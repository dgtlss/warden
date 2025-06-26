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
     *                   'package' => 'package-name',
     *                   'title' => 'Issue title',
     *                   'severity' => 'critical|high|medium|low',
     *                   'description' => 'Detailed description',
     *                   'cve' => 'CVE-2023-XXXXX', // optional
     *                   'affected_versions' => '< 2.0', // optional
     *               ]
     */
    public function getFindings(): array;

    /**
     * Get the name of this audit.
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Get the description of what this audit checks.
     *
     * @return string
     */
    public function getDescription(): string;

    /**
     * Determine if this audit should be run.
     *
     * @return bool
     */
    public function shouldRun(): bool;
} 