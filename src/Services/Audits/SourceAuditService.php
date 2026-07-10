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
        if ($this->timedOut($startedAt, $auditContext->timeout)) {
            $errors[] = new AuditError($this->getName(), 'timeout', 'Source discovery exceeded the configured timeout.');

            return new AuditResult($this->getName(), [], $errors);
        }

        $findings = $this->textSourceAnalyzer->secrets($files['secrets']);
        if ($this->timedOut($startedAt, $auditContext->timeout)) {
            $errors[] = new AuditError($this->getName(), 'timeout', 'Secret analysis exceeded the configured timeout.');

            return new AuditResult($this->getName(), $findings, $errors);
        }

        array_push($findings, ...$this->textSourceAnalyzer->blade($files['blade']));

        foreach ($files['php'] as $file) {
            if ($this->timedOut($startedAt, $auditContext->timeout)) {
                $errors[] = new AuditError($this->getName(), 'timeout', 'Source analysis exceeded the configured timeout.');
                break;
            }

            $result = $this->phpSourceAnalyzer->analyze($file);
            array_push($findings, ...$result['findings']);
            array_push($errors, ...$result['errors']);
        }

        return new AuditResult($this->getName(), $findings, $errors);
    }

    /** @phpstan-impure */
    protected function timedOut(float $startedAt, int $timeout): bool
    {
        return (microtime(true) - $startedAt) >= $timeout;
    }
}
