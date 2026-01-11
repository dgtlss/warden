<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;

class ComposerAuditService extends AbstractAuditService
{
    /**
     * @var array<int, array<string, mixed>>
     */
    private array $abandonedPackages = [];

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
            $rawOutput = $process->getOutput();
            $output = json_decode($rawOutput, true);
            if (!is_array($output)) {
                $errorOutput = $process->getErrorOutput() ?: ($rawOutput ?: 'No error output available');
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
            if (isset($output['abandoned']) && is_array($output['abandoned']) && !empty($output['abandoned'])) {
                /** @var array<string, string|true> $abandoned */
                $abandoned = $output['abandoned'];
                foreach ($abandoned as $package => $replacement) {
                    $this->abandonedPackages[] = [
                        'package' => $package,
                        'replacement' => is_string($replacement) ? $replacement : null
                    ];
                }
            }

            // Handle security advisories
            if (isset($output['advisories']) && is_array($output['advisories']) && !empty($output['advisories'])) {
                /** @var array<string, array<int, array<string, mixed>>> $advisories */
                $advisories = $output['advisories'];
                foreach ($advisories as $package => $issues) {
                    foreach ($issues as $issue) {
                        $this->addFinding([
                            'source' => $this->getName(),
                            'package' => $package,
                            'title' => is_string($issue['title'] ?? null) ? $issue['title'] : 'Unknown vulnerability',
                            'severity' => is_string($issue['severity'] ?? null) ? $issue['severity'] : 'unknown',
                            'cve' => is_string($issue['cve'] ?? null) ? $issue['cve'] : null,
                            'affected_versions' => is_string($issue['affectedVersions'] ?? null) ? $issue['affectedVersions'] : null
                        ]);
                    }
                }
            }

            return true;
        } catch (\Exception $exception) {
            $this->addFinding([
                'source' => $this->getName(),
                'package' => 'composer',
                'title' => 'Composer audit failed with exception',
                'severity' => 'high',
                'error' => $exception->getMessage()
            ]);
            
            info("Composer audit exception: " . $exception->getMessage());
            return false;
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function getAbandonedPackages(): array
    {
        return $this->abandonedPackages;
    }
}