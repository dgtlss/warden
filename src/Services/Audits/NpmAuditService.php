<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;

class NpmAuditService extends AbstractAuditService
{
    public function getName(): string
    {
        return 'npm';
    }

    public function run(): bool
    {
        if (!file_exists(base_path('package.json'))) {
            $this->addFinding([
                'package' => 'npm',
                'title' => 'Missing package.json',
                'severity' => 'error',
                'cve' => null,
                'affected_versions' => null
            ]);
            return false;
        }

        if (!file_exists(base_path('package-lock.json'))) {
            $this->addFinding([
                'package' => 'npm',
                'title' => 'Missing package-lock.json',
                'severity' => 'error',
                'cve' => null,
                'affected_versions' => null
            ]);
            return false;
        }

        $process = $this->createProcess(['npm', 'audit', '--json']);
        $process->setWorkingDirectory(base_path());
        $timeout = config('warden.audits.timeout', 300);
        $process->setTimeout(is_numeric($timeout) ? (float) $timeout : 300.0);

        try {
            $process->run();
            
            // npm audit returns non-zero exit codes when vulnerabilities are found, which is normal
            // Only treat it as an error if we can't parse the JSON output
            $rawOutput = $process->getOutput();
            $output = json_decode($rawOutput, true);
            
            if (!is_array($output)) {
                $errorOutput = $process->getErrorOutput() ?: ($rawOutput ?: 'No error output available');
                $exitCode = $process->getExitCode();
                
                $this->addFinding([
                    'package' => 'npm',
                    'title' => 'npm audit failed to run',
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => null,
                    'error' => "Exit Code: {$exitCode}\nError: {$errorOutput}"
                ]);
                return false;
            }

            // Handle modern npm audit format (npm 7+)
            if (isset($output['vulnerabilities']) && is_array($output['vulnerabilities'])) {
                /** @var array<string, array<string, mixed>> $vulnerabilities */
                $vulnerabilities = $output['vulnerabilities'];
                foreach ($vulnerabilities as $package => $vulnerability) {
                    // Modern format has vulnerability details in the 'via' array
                    if (isset($vulnerability['via']) && is_array($vulnerability['via'])) {
                        foreach ($vulnerability['via'] as $viaItem) {
                            // Skip string entries (they're just package names), process array entries
                            if (is_array($viaItem)) {
                                $this->addFinding([
                                    'package' => $package,
                                    'title' => is_string($viaItem['title'] ?? null) ? $viaItem['title'] : 'Unknown vulnerability',
                                    'severity' => is_string($viaItem['severity'] ?? null) ? $viaItem['severity'] : 'unknown',
                                    'cve' => is_string($viaItem['url'] ?? null) ? $viaItem['url'] : null,
                                    'affected_versions' => is_string($viaItem['range'] ?? null) ? $viaItem['range'] : (is_string($vulnerability['range'] ?? null) ? $vulnerability['range'] : 'unknown')
                                ]);
                            }
                        }
                    } else {
                        // Fallback for potential legacy format or missing via array
                        $this->addFinding([
                            'package' => $package,
                            'title' => is_string($vulnerability['title'] ?? null) ? $vulnerability['title'] : 'Unknown vulnerability',
                            'severity' => is_string($vulnerability['severity'] ?? null) ? $vulnerability['severity'] : 'unknown',
                            'cve' => is_string($vulnerability['url'] ?? null) ? $vulnerability['url'] : null,
                            'affected_versions' => is_string($vulnerability['range'] ?? null) ? $vulnerability['range'] : 'unknown'
                        ]);
                    }
                }
            }
            
            // Handle legacy npm audit format (npm v6 and earlier) - advisories format
            if (isset($output['advisories']) && is_array($output['advisories'])) {
                /** @var array<int|string, array<string, mixed>> $advisories */
                $advisories = $output['advisories'];
                foreach ($advisories as $advisory) {
                    /** @var array<int, string> $cves */
                    $cves = is_array($advisory['cves'] ?? null) ? $advisory['cves'] : [];
                    $this->addFinding([
                        'package' => is_string($advisory['module_name'] ?? null) ? $advisory['module_name'] : 'unknown',
                        'title' => is_string($advisory['title'] ?? null) ? $advisory['title'] : 'Unknown vulnerability',
                        'severity' => is_string($advisory['severity'] ?? null) ? $advisory['severity'] : 'unknown',
                        'cve' => $cves[0] ?? (is_string($advisory['url'] ?? null) ? $advisory['url'] : null),
                        'affected_versions' => is_string($advisory['vulnerable_versions'] ?? null) ? $advisory['vulnerable_versions'] : 'unknown'
                    ]);
                }
            }

            return true;
        } catch (\Exception $exception) {
            $this->addFinding([
                'package' => 'npm',
                'title' => 'npm audit failed with exception',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null,
                'error' => $exception->getMessage()
            ]);
            return false;
        }
    }

    /**
     * @param array<int, string> $command
     */
    protected function createProcess(array $command): Process
    {
        return new Process($command);
    }
}