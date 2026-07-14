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

class NpmAuditService implements AuditServiceInterface
{
    public function getName(): string
    {
        return 'npm';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        if (!is_file(base_path('package-lock.json'))) {
            return AuditResult::complete($this->getName());
        }

        $command = ['npm', 'audit', '--json', '--package-lock-only'];
        if ($auditContext->scope === 'production') {
            $command[] = '--omit=dev';
        }

        $process = $this->createProcess($command, $auditContext->timeout);
        try {
            $process->run();
        } catch (ProcessTimedOutException) {
            return AuditResult::failed($this->getName(), 'timeout', 'npm audit exceeded the configured timeout.');
        }

        try {
            $decoded = json_decode($process->getOutput(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            return AuditResult::failed(
                $this->getName(),
                'malformed_output',
                trim($process->getErrorOutput()) ?: $jsonException->getMessage(),
            );
        }

        if (!is_array($decoded)) {
            return AuditResult::failed($this->getName(), 'malformed_output', 'npm audit returned an unexpected JSON value.');
        }

        $findings = $this->findingsFrom($decoded['vulnerabilities'] ?? []);
        if (!$process->isSuccessful() && $findings === []) {
            return AuditResult::failed(
                $this->getName(),
                'scanner_failed',
                $this->npmError($decoded, $process),
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
    private function findingsFrom(mixed $vulnerabilities): array
    {
        if (!is_array($vulnerabilities)) {
            return [];
        }

        $findings = [];
        foreach ($vulnerabilities as $package => $vulnerability) {
            if (!is_string($package) || !is_array($vulnerability)) {
                continue;
            }

            $advisories = array_values(array_filter(
                is_array($vulnerability['via'] ?? null) ? $vulnerability['via'] : [],
                'is_array',
            ));
            if ($advisories === []) {
                $advisories = [$vulnerability];
            }

            foreach ($advisories as $advisory) {
                $url = is_string($advisory['url'] ?? null) ? $advisory['url'] : null;
                $identifier = is_int($advisory['source'] ?? null)
                    ? (string) $advisory['source']
                    : ($url ?? (is_string($advisory['title'] ?? null) ? $advisory['title'] : 'unknown'));
                $findings[] = new Finding(
                    id: 'npm.advisory.' . hash('sha256', $identifier),
                    source: $this->getName(),
                    title: is_string($advisory['title'] ?? null) ? $advisory['title'] : 'Dependency security advisory',
                    severity: Severity::fromScannerValue($advisory['severity'] ?? $vulnerability['severity'] ?? null),
                    description: sprintf('%s contains a known vulnerability.', $package),
                    remediation: 'Upgrade the dependency using the remediation provided by npm.',
                    package: $package,
                    reference: $url,
                    path: 'package-lock.json',
                    metadata: array_filter([
                        'affected_versions' => is_string($advisory['range'] ?? null)
                            ? $advisory['range']
                            : (is_string($vulnerability['range'] ?? null) ? $vulnerability['range'] : null),
                    ], static fn (mixed $value): bool => $value !== null),
                );
            }
        }

        return $findings;
    }

    /** @param array<string, mixed> $decoded */
    private function npmError(array $decoded, Process $process): string
    {
        $message = $decoded['error']['summary'] ?? $decoded['error']['detail'] ?? null;

        return is_string($message) && $message !== ''
            ? $message
            : (trim($process->getErrorOutput()) ?: sprintf('npm audit exited with code %d.', $process->getExitCode()));
    }
}
