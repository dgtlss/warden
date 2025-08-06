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

        $process = new Process(['npm', 'audit', '--json']);
        $process->setWorkingDirectory(base_path());
        $process->setTimeout(config('warden.audits.timeout', 300));

        try {
            $process->run();
            
            // npm audit returns non-zero exit codes when vulnerabilities are found, which is normal
            // Only treat it as an error if we can't parse the JSON output
            $output = json_decode($process->getOutput(), true);
            if ($output === null) {
                $errorOutput = $process->getErrorOutput() ?: $process->getOutput() ?: 'No error output available';
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
            if (isset($output['vulnerabilities'])) {
                foreach ($output['vulnerabilities'] as $package => $vulnerability) {
                    // Modern format has vulnerability details in the 'via' array
                    if (isset($vulnerability['via']) && is_array($vulnerability['via'])) {
                        foreach ($vulnerability['via'] as $viaItem) {
                            // Skip string entries (they're just package names), process array entries
                            if (is_array($viaItem)) {
                                $this->addFinding([
                                    'package' => $package,
                                    'title' => $viaItem['title'] ?? 'Unknown vulnerability',
                                    'severity' => $viaItem['severity'] ?? 'unknown',
                                    'cve' => $viaItem['url'] ?? null,
                                    'affected_versions' => $viaItem['range'] ?? ($vulnerability['range'] ?? 'unknown')
                                ]);
                            }
                        }
                    } else {
                        // Fallback for potential legacy format or missing via array
                        $this->addFinding([
                            'package' => $package,
                            'title' => $vulnerability['title'] ?? 'Unknown vulnerability',
                            'severity' => $vulnerability['severity'] ?? 'unknown',
                            'cve' => $vulnerability['url'] ?? null,
                            'affected_versions' => $vulnerability['range'] ?? 'unknown'
                        ]);
                    }
                }
            }
            
            // Handle legacy npm audit format (npm v6 and earlier) - advisories format
            if (isset($output['advisories'])) {
                foreach ($output['advisories'] as $advisory) {
                    $this->addFinding([
                        'package' => $advisory['module_name'] ?? 'unknown',
                        'title' => $advisory['title'] ?? 'Unknown vulnerability',
                        'severity' => $advisory['severity'] ?? 'unknown',
                        'cve' => $advisory['cves'][0] ?? $advisory['url'] ?? null,
                        'affected_versions' => $advisory['vulnerable_versions'] ?? 'unknown'
                    ]);
                }
            }

            return true;
        } catch (\Exception $e) {
            $this->addFinding([
                'package' => 'npm',
                'title' => 'npm audit failed with exception',
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => null,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }
}