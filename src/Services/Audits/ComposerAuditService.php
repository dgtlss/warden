<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use JsonException;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

class ComposerAuditService implements AuditServiceInterface
{
    public function getName(): string
    {
        return 'composer';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        if (!is_file(base_path('composer.lock'))) {
            return AuditResult::complete($this->getName());
        }

        $command = ['composer', 'audit', '--locked', '--format=json', '--no-interaction', '--abandoned=report'];
        if ($auditContext->scope === 'production') {
            $command[] = '--no-dev';
        }

        $process = $this->createProcess($command, $auditContext->timeout);

        try {
            $process->run();
        } catch (ProcessTimedOutException) {
            return AuditResult::failed($this->getName(), 'timeout', 'Composer audit exceeded the configured timeout.');
        }

        $output = trim($process->getOutput());
        if ($output === '') {
            return AuditResult::failed(
                $this->getName(),
                'scanner_failed',
                trim($process->getErrorOutput()) ?: 'Composer audit produced no JSON output.',
            );
        }

        try {
            $decoded = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            return AuditResult::failed($this->getName(), 'malformed_output', $jsonException->getMessage());
        }

        if (!is_array($decoded)) {
            return AuditResult::failed($this->getName(), 'malformed_output', 'Composer audit returned an unexpected JSON value.');
        }

        $findings = [
            ...$this->advisoryFindings($decoded['advisories'] ?? []),
            ...$this->abandonedFindings($decoded['abandoned'] ?? []),
            ...$this->malwareFindings($decoded['malware'] ?? $decoded['malicious'] ?? []),
        ];

        if (!$process->isSuccessful() && $findings === []) {
            return AuditResult::failed(
                $this->getName(),
                'scanner_failed',
                trim($process->getErrorOutput()) ?: sprintf('Composer audit exited with code %d.', $process->getExitCode()),
            );
        }

        return AuditResult::complete($this->getName(), $findings);
    }

    /** @param list<string> $command */
    protected function createProcess(array $command, int $timeout): Process
    {
        $process = new Process($command, base_path());
        $process->setTimeout($timeout);

        return $process;
    }

    /** @return list<Finding> */
    private function advisoryFindings(mixed $advisories): array
    {
        if (!is_array($advisories)) {
            return [];
        }

        $findings = [];
        foreach ($advisories as $package => $issues) {
            if (!is_string($package) || !is_array($issues)) {
                continue;
            }

            foreach ($issues as $issue) {
                if (!is_array($issue)) {
                    continue;
                }

                $advisoryId = $this->stringValue($issue['advisoryId'] ?? $issue['cve'] ?? null) ?? 'unknown';
                $reference = $this->stringValue($issue['link'] ?? $issue['url'] ?? $issue['cve'] ?? null);
                $findings[] = new Finding(
                    id: 'composer.advisory.' . strtolower($advisoryId),
                    source: $this->getName(),
                    title: $this->stringValue($issue['title'] ?? null) ?? 'Dependency security advisory',
                    severity: Severity::fromScannerValue($issue['severity'] ?? null),
                    description: sprintf('%s is affected by advisory %s.', $package, $advisoryId),
                    remediation: 'Upgrade the package to a version outside the affected range.',
                    package: $package,
                    reference: $reference,
                    path: 'composer.lock',
                    metadata: array_filter([
                        'affected_versions' => $this->stringValue($issue['affectedVersions'] ?? null),
                    ], static fn (mixed $value): bool => $value !== null),
                );
            }
        }

        return $findings;
    }

    /** @return list<Finding> */
    private function abandonedFindings(mixed $abandoned): array
    {
        if (!is_array($abandoned)) {
            return [];
        }

        $findings = [];
        foreach ($abandoned as $package => $replacement) {
            if (!is_string($package)) {
                continue;
            }

            $replacement = is_string($replacement) && $replacement !== '' ? $replacement : null;
            $findings[] = new Finding(
                id: 'composer.abandoned',
                source: $this->getName(),
                title: 'Abandoned Composer package',
                severity: Severity::Medium,
                description: sprintf('%s is no longer maintained.', $package),
                remediation: $replacement === null ? 'Replace or remove the package.' : 'Migrate to ' . $replacement . '.',
                package: $package,
                path: 'composer.lock',
                metadata: $replacement === null ? [] : ['replacement' => $replacement],
            );
        }

        return $findings;
    }

    /** @return list<Finding> */
    private function malwareFindings(mixed $malware): array
    {
        if (!is_array($malware)) {
            return [];
        }

        $findings = [];
        foreach ($malware as $package => $details) {
            if (!is_string($package)) {
                continue;
            }

            $findings[] = new Finding(
                id: 'composer.malware',
                source: $this->getName(),
                title: 'Package identified as malicious',
                severity: Severity::Critical,
                description: sprintf('%s was identified by Composer as malicious.', $package),
                remediation: 'Remove the package and investigate the affected build immediately.',
                package: $package,
                reference: is_array($details) ? $this->stringValue($details['link'] ?? $details['url'] ?? null) : null,
                path: 'composer.lock',
            );
        }

        return $findings;
    }

    private function stringValue(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
