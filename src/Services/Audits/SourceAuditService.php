<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\Services\Source\PhpSourceAnalyzer;
use Dgtlss\Warden\Services\Source\SourceFileDiscovery;
use Dgtlss\Warden\Services\Source\TextSourceAnalyzer;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditResult;

class SourceAuditService implements AuditServiceInterface
{
    public function __construct(
        private readonly SourceFileDiscovery $sourceFileDiscovery,
        private readonly PhpSourceAnalyzer $phpSourceAnalyzer,
        private readonly TextSourceAnalyzer $textSourceAnalyzer,
    ) {
    }

    public function getName(): string
    {
        return 'source';
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        $startedAt = microtime(true);
        $files = $this->sourceFileDiscovery->discover();
        $errors = $files['errors'];
        $pending = [];
        foreach ([...$files['php'], ...$files['blade'], ...$files['secrets']] as $file) {
            $pending[$file->getPathname()] = ($pending[$file->getPathname()] ?? 0) + 1;
        }

        if ($this->timedOut($startedAt, $auditContext->timeout)) {
            $errors[] = new AuditError($this->getName(), 'timeout', 'Source discovery exceeded the configured timeout.');

            return $this->result([], $errors, $pending, $files['skipped']);
        }

        $findings = $this->textSourceAnalyzer->secrets($files['secrets']);
        foreach ($files['secrets'] as $file) {
            $pending[$file->getPathname()]--;
        }

        if ($this->timedOut($startedAt, $auditContext->timeout)) {
            $errors[] = new AuditError($this->getName(), 'timeout', 'Secret analysis exceeded the configured timeout.');

            return $this->result($findings, $errors, $pending, $files['skipped']);
        }

        array_push($findings, ...$this->textSourceAnalyzer->blade($files['blade']));
        foreach ($files['blade'] as $file) {
            $pending[$file->getPathname()]--;
        }

        if ($this->timedOut($startedAt, $auditContext->timeout)) {
            $errors[] = new AuditError($this->getName(), 'timeout', 'Source analysis exceeded the configured timeout.');

            return $this->result($findings, $errors, $pending, $files['skipped']);
        }

        foreach ($files['php'] as $file) {
            if ($this->timedOut($startedAt, $auditContext->timeout)) {
                $errors[] = new AuditError($this->getName(), 'timeout', 'Source analysis exceeded the configured timeout.');
                break;
            }

            $result = $this->phpSourceAnalyzer->analyze($file);
            $pending[$file->getPathname()]--;
            array_push($findings, ...$result['findings']);
            array_push($errors, ...$result['errors']);
        }

        return $this->result($findings, $errors, $pending, $files['skipped']);
    }

    /**
     * @param list<\Dgtlss\Warden\ValueObjects\Finding> $findings
     * @param list<AuditError> $errors
     * @param array<string, int> $pending
     */
    private function result(array $findings, array $errors, array $pending, int $skipped): AuditResult
    {
        $completed = count(array_filter($pending, static fn (int $remaining): bool => $remaining === 0));

        return new AuditResult($this->getName(), $findings, $errors, coverage: [
            'scanned' => $completed,
            'skipped' => $skipped + count($pending) - $completed,
            'errors' => count($errors),
        ]);
    }

    /** @phpstan-impure */
    protected function timedOut(float $startedAt, int $timeout): bool
    {
        return (microtime(true) - $startedAt) >= $timeout;
    }
}
