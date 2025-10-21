<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;
use Dgtlss\Warden\Services\Dependencies\SystemCommandDependency;
use Dgtlss\Warden\Services\Dependencies\FileDependency;

class ComposerAuditService extends AbstractAuditService
{
    private $abandonedPackages = [];

    public function getName(): string
    {
        return 'composer';
    }

    /**
     * Called when the audit is initialized.
     *
     * @return void
     */
    protected function onInitialize(): void
    {
        // Add Composer command dependency
        $composerDep = new SystemCommandDependency('composer', ['--version']);
        $this->addDependency($composerDep);

        // Add composer.json file dependency
        $composerJsonDep = new FileDependency('composer.json', true, false);
        $this->addDependency($composerJsonDep);

        // Add composer.lock file dependency (optional but recommended)
        $composerLockDep = new FileDependency('composer.lock', true, false);
        $this->addDependency($composerLockDep);
    }

    /**
     * Get the default configuration for this audit.
     *
     * @return array
     */
    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'ignore_abandoned' => false,
            'format' => 'json',
            'working_directory' => base_path(),
        ]);
    }

    public function run(): bool
    {
        if (!$this->shouldRun()) {
            $this->info('Audit should not run - skipping');
            return true;
        }

        $workingDirectory = $this->getConfigValue('working_directory', base_path());
        $format = $this->getConfigValue('format', 'json');
        
        $process = new Process(['composer', 'audit', "--format={$format}"]);
        $process->setWorkingDirectory($workingDirectory);
        $process->setTimeout($this->getTimeout());
        
        $this->info("Running composer audit from: {$workingDirectory}");
        
        try {
            $process->run();
            
            // Exit code 1 from composer audit means vulnerabilities were found, which is okay
            // Only treat it as an error if we can't parse the output as JSON
            $output = json_decode($process->getOutput(), true);
            if ($output === null) {
                $errorOutput = $process->getErrorOutput() ?: $process->getOutput() ?: 'No error output available';
                $exitCode = $process->getExitCode();
                
                $this->addFinding([
                    'package' => 'composer',
                    'title' => 'Composer audit failed to run',
                    'severity' => 'high',
                    'error' => "Exit Code: {$exitCode}\nError: {$errorOutput}"
                ]);
                
                $this->error("Composer audit failed", [
                    'exit_code' => $exitCode,
                    'error' => $errorOutput
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

                // Log abandoned packages if not ignored
                if (!$this->getConfigValue('ignore_abandoned', false)) {
                    $this->warning('Found abandoned packages', ['count' => count($this->abandonedPackages)]);
                }
            }

            // Handle security advisories
            if (isset($output['advisories']) && !empty($output['advisories'])) {
                foreach ($output['advisories'] as $package => $issues) {
                    foreach ($issues as $issue) {
                        $this->addFinding([
                            'package' => $package,
                            'title' => $issue['title'],
                            'severity' => $issue['severity'] ?? 'unknown',
                            'cve' => $issue['cve'] ?? null,
                            'affected_versions' => $issue['affectedVersions'] ?? null,
                            'link' => $issue['link'] ?? null,
                            'reported_at' => $issue['reportedAt'] ?? null
                        ]);
                    }
                }
            }

            return true;
        } catch (\Exception $e) {
            $this->addFinding([
                'package' => 'composer',
                'title' => 'Composer audit failed with exception',
                'severity' => 'high',
                'error' => $e->getMessage()
            ]);
            
            $this->error("Composer audit exception: " . $e->getMessage());
            return false;
        }
    }

    public function getAbandonedPackages(): array
    {
        return $this->abandonedPackages;
    }
}