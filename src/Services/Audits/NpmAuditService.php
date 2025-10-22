<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;
use Dgtlss\Warden\Services\Dependencies\SystemCommandDependency;
use Dgtlss\Warden\Services\Dependencies\FileDependency;

class NpmAuditService extends AbstractAuditService
{
    public function getName(): string
    {
        return 'npm';
    }

    /**
     * Called when the audit is initialized.
     *
     * @return void
     */
    protected function onInitialize(): void
    {
        // Add NPM command dependency
        $npmDep = new SystemCommandDependency('npm', ['--version']);
        $this->addDependency($npmDep);

        // Add package.json file dependency
        $packageJsonDep = new FileDependency('package.json', true, false);
        $this->addDependency($packageJsonDep);

        // Add package-lock.json file dependency (recommended)
        $packageLockDep = new FileDependency('package-lock.json', true, false);
        $this->addDependency($packageLockDep);
    }

    /**
     * Get the default configuration for this audit.
     *
     * @return array
     */
    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'format' => 'json',
            'working_directory' => base_path(),
            'require_lockfile' => true,
        ]);
    }

    /**
     * Called to determine if the audit should run.
     *
     * @return bool
     */
    protected function onShouldRun(): bool
    {
        // Only run if package.json exists
        if (!file_exists(base_path('package.json'))) {
            $this->info('package.json not found - skipping NPM audit');
            return false;
        }

        // Check if lockfile is required
        if ($this->getConfigValue('require_lockfile', true) && !file_exists(base_path('package-lock.json'))) {
            $this->warning('package-lock.json not found but is required - skipping NPM audit');
            return false;
        }

        return parent::onShouldRun();
    }

    public function run(): bool
    {
        if (!$this->shouldRun()) {
            $this->info('Audit should not run - skipping');
            return true;
        }

        $workingDirectory = $this->getConfigValue('working_directory', base_path());
        $format = $this->getConfigValue('format', 'json');
        
        // Use --json flag instead of deprecated --format flag for npm audit
        $process = new Process(['npm', 'audit', '--json']);
        $process->setWorkingDirectory($workingDirectory);
        $process->setTimeout($this->getTimeout());

        $this->info("Running NPM audit from: {$workingDirectory}");

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
                    'error' => "Exit Code: {$exitCode}\nError: {$errorOutput}"
                ]);
                
                $this->error("NPM audit failed", [
                    'exit_code' => $exitCode,
                    'error' => $errorOutput
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
                'error' => $e->getMessage()
            ]);
            
            $this->error("NPM audit exception: " . $e->getMessage());
            return false;
        }
    }
}