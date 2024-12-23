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
        $process->run();

        if (!$process->isSuccessful()) {
            $this->addFinding([
                'package' => 'npm',
                'title' => 'npm audit command failed',
                'severity' => 'error',
                'cve' => null,
                'affected_versions' => null,
                'details' => $process->getErrorOutput() ?: 'No error output available'
            ]);
            return false;
        }

        $output = json_decode($process->getOutput(), true);
        
        if (isset($output['vulnerabilities'])) {
            foreach ($output['vulnerabilities'] as $package => $vuln) {
                $this->addFinding([
                    'package' => $package,
                    'title' => $vuln['title'] ?? 'Unknown',
                    'severity' => $vuln['severity'] ?? 'unknown',
                    'cve' => $vuln['url'] ?? null,
                    'affected_versions' => $vuln['range'] ?? 'unknown'
                ]);
            }
        }

        return true;
    }
}