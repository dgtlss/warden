<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\AuditServiceInterface;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use Throwable;

final class AuditExecutor
{
    /**
     * @param list<AuditServiceInterface> $audits
     * @param callable(string, string, ?float): void|null $onProgress
     * @return list<AuditResult>
     */
    public function execute(AuditContext $auditContext, array $audits, ?callable $onProgress = null): array
    {
        $results = [];

        foreach ($audits as $audit) {
            $name = $audit->getName();
            if ($onProgress !== null) {
                $onProgress($name, 'running', null);
            }

            $startedAt = microtime(true);

            try {
                $result = $audit->run($auditContext);
                if (!$this->isValidResult($name, $result)) {
                    $result = AuditResult::failed($name, 'invalid_result', 'The audit returned an invalid or mismatched result.');
                }
            } catch (Throwable $throwable) {
                $result = AuditResult::failed($name, 'unhandled_exception', $throwable->getMessage());
            }

            $duration = round((microtime(true) - $startedAt) * 1000, 1);
            $result = $result->withDuration($duration);
            $results[] = $result;
            if ($onProgress !== null) {
                $onProgress($name, $result->succeeded() ? 'done' : 'failed', $duration);
            }
        }

        return $results;
    }

    private function isValidResult(string $audit, AuditResult $auditResult): bool
    {
        if ($auditResult->audit !== $audit) {
            return false;
        }

        if (!$this->containsOnly($auditResult->findings, Finding::class)) {
            return false;
        }

        if (!$this->containsOnly($auditResult->errors, AuditError::class)) {
            return false;
        }

        foreach ($auditResult->errors as $error) {
            if ($error->audit !== $audit) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<mixed> $items
     * @param class-string $type
     */
    private function containsOnly(array $items, string $type): bool
    {
        foreach ($items as $item) {
            if (!$item instanceof $type) {
                return false;
            }
        }

        return true;
    }
}
