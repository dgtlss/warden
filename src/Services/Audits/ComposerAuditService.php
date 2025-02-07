<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;

class ComposerAuditService extends AbstractAuditService
{
    private $abandonedPackages = [];

    public function getName(): string
    {
        return 'composer';
    }

    public function run(): bool
    {
        $process = new Process(['composer', 'audit', '--format=json']);
        $process->setWorkingDirectory(base_path());
        $process->setTimeout(60);
        
        // Add debug output before running
        info("Running composer audit from: " . base_path());
        
        try {
            $process->run();
            
            // Exit code 1 from composer audit means vulnerabilities were found, which is okay
            // Only treat it as an error if we can't parse the output as JSON
            $output = json_decode($process->getOutput(), true);
            if ($output === null) {
                $errorOutput = $process->getErrorOutput() ?: $process->getOutput() ?: 'No error output available';
                $exitCode = $process->getExitCode();
                
                $this->addFinding([
                    'source' => $this->getName(),
                    'package' => 'composer',
                    'title' => 'Composer audit failed to run',
                    'severity' => 'high',
                    'error' => "Exit Code: {$exitCode}\nError: {$errorOutput}"
                ]);
                
                return false;
            }

            // Handle abandoned packages (but don't fail the audit)
            if (isset($output['abandoned']) && !empty($output['abandoned'])) {
                foreach ($output['abandoned'] as $package => $replacement) {
                    $this->abandonedPackages[] = [
                        'package' => $package,
                        'replacement' => is_string($replacement) ? $replacement : null
                    ];
                }
            }

            // Handle security advisories
            if (isset($output['advisories']) && !empty($output['advisories'])) {
                foreach ($output['advisories'] as $package => $issues) {
                    foreach ($issues as $issue) {
                        $this->addFinding([
                            'source' => $this->getName(),
                            'package' => $package,
                            'title' => $issue['title'],
                            'severity' => $issue['severity'] ?? 'unknown',
                            'cve' => $issue['cve'] ?? null,
                            'affected_versions' => $issue['affectedVersions'] ?? null
                        ]);
                    }
                }
            }

            return true;
        } catch (\Exception $e) {
            $this->addFinding([
                'source' => $this->getName(),
                'package' => 'composer',
                'title' => 'Composer audit failed with exception',
                'severity' => 'high',
                'error' => $e->getMessage()
            ]);
            
            info("Composer audit exception: " . $e->getMessage());
            return false;
        }
    }

    public function getAbandonedPackages(): array
    {
        return $this->abandonedPackages;
    }
}