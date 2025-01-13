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
        $process->run();

        if (!$process->isSuccessful()) {
            return false;
        }

        $output = json_decode($process->getOutput(), true);
        
        // Handle abandoned packages
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
                        'package' => $package,
                        'title' => $issue['title'],
                        'severity' => $issue['severity'] ?? 'unknown',
                        'cve' => $issue['cve'],
                        'affected_versions' => $issue['affected_versions']
                    ]);
                }
            }
        }

        return true;
    }

    public function getAbandonedPackages(): array
    {
        return $this->abandonedPackages;
    }
}