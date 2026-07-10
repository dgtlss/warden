<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services;

use Carbon\CarbonImmutable;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditReport;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;
use JsonException;
use Throwable;

final class SuppressionService
{
    /** @return list<AuditError> */
    public function errors(bool $includeBaseline = true, ?CarbonImmutable $now = null): array
    {
        [, $errors] = $this->configuredRules($now ?? CarbonImmutable::now());
        if ($includeBaseline) {
            [, $baselineErrors] = $this->baselineRules($now ?? CarbonImmutable::now());
            array_push($errors, ...$baselineErrors);
        }

        return $errors;
    }

    public function apply(AuditReport $auditReport, bool $includeBaseline = true): AuditReport
    {
        [$rules, $errors] = $this->configuredRules($auditReport->scannedAt ?? CarbonImmutable::now());
        if ($includeBaseline) {
            [$baselineRules, $baselineErrors] = $this->baselineRules($auditReport->scannedAt ?? CarbonImmutable::now());
            array_push($rules, ...$baselineRules);
            array_push($errors, ...$baselineErrors);
        }

        $ignored = [];
        $results = [];

        foreach ($auditReport->audits as $audit) {
            $active = [];
            foreach ($audit->findings as $finding) {
                if ($this->isIgnored($finding, $rules)) {
                    $ignored[] = $finding;
                } else {
                    $active[] = $finding;
                }
            }

            $results[] = new AuditResult($audit->audit, $active, $audit->errors, $audit->durationMs);
        }

        return $auditReport->withFilteredFindings(
            $results,
            $ignored,
            [...$auditReport->configurationErrors, ...$errors],
        );
    }

    /**
     * @param list<array{id: string, fingerprint: string|null}> $rules
     */
    private function isIgnored(Finding $finding, array $rules): bool
    {
        foreach ($rules as $rule) {
            if ($rule['id'] !== $finding->id) {
                continue;
            }

            if ($rule['fingerprint'] === null || hash_equals($rule['fingerprint'], $finding->fingerprint())) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{0: list<array{id: string, fingerprint: string|null}>, 1: list<AuditError>}
     */
    private function configuredRules(CarbonImmutable $now): array
    {
        $configured = config('warden.ignore_findings', []);
        if (!is_array($configured)) {
            return [[], [new AuditError('configuration', 'invalid_suppressions', 'warden.ignore_findings must be an array.')]];
        }

        return $this->validateRules($configured, $now, 'configuration');
    }

    /**
     * @return array{0: list<array{id: string, fingerprint: string|null}>, 1: list<AuditError>}
     */
    private function baselineRules(CarbonImmutable $now): array
    {
        $configuredPath = (string) config('warden.baseline.file', 'warden-baseline.json');
        $path = str_starts_with($configuredPath, DIRECTORY_SEPARATOR) ? $configuredPath : base_path($configuredPath);
        if (!is_file($path)) {
            return [[], []];
        }

        $contents = file_get_contents($path);
        if (!is_string($contents)) {
            return [[], [new AuditError('baseline', 'baseline_unreadable', 'The Warden baseline could not be read.')]];
        }

        try {
            $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            return [[], [new AuditError('baseline', 'baseline_invalid', $jsonException->getMessage())]];
        }

        if (!is_array($decoded) || ($decoded['schema_version'] ?? null) !== '1.0.0' || !is_array($decoded['findings'] ?? null)) {
            return [[], [new AuditError('baseline', 'baseline_invalid', 'The Warden baseline has an unsupported schema.')]];
        }

        return $this->validateRules($decoded['findings'], $now, 'baseline', true);
    }

    /**
     * @param array<mixed> $configured
     * @return array{0: list<array{id: string, fingerprint: string|null}>, 1: list<AuditError>}
     */
    private function validateRules(array $configured, CarbonImmutable $now, string $source, bool $fingerprintRequired = false): array
    {
        $rules = [];
        $errors = [];

        foreach ($configured as $index => $rule) {
            if (!is_array($rule)) {
                $errors[] = new AuditError($source, 'suppression_invalid', sprintf('Suppression %s must be an object.', $index));
                continue;
            }

            $id = $rule['id'] ?? null;
            $reason = $rule['reason'] ?? null;
            $expiresAt = $rule['expires_at'] ?? null;
            $fingerprint = $rule['fingerprint'] ?? null;

            if (!is_string($id) || $id === '' || !is_string($reason) || $reason === '' || !is_string($expiresAt) || $expiresAt === '') {
                $errors[] = new AuditError($source, 'suppression_invalid', sprintf('Suppression %s requires id, reason, and expires_at.', $index));
                continue;
            }

            if (preg_match('/^\d{4}-\d{2}-\d{2}$/D', $expiresAt) !== 1) {
                $errors[] = new AuditError($source, 'suppression_invalid', sprintf('Suppression %s expires_at must use YYYY-MM-DD.', $index));
                continue;
            }

            if ($fingerprintRequired && (!is_string($fingerprint) || $fingerprint === '')) {
                $errors[] = new AuditError($source, 'suppression_invalid', sprintf('Baseline entry %s requires a fingerprint.', $index));
                continue;
            }

            try {
                $expiry = CarbonImmutable::parse($expiresAt)->endOfDay();
            } catch (Throwable) {
                $errors[] = new AuditError($source, 'suppression_invalid', sprintf('Suppression %s has an invalid expires_at date.', $index));
                continue;
            }

            if ($expiry->isBefore($now)) {
                $errors[] = new AuditError($source, 'suppression_expired', sprintf('Suppression for %s expired on %s.', $id, $expiresAt));
                continue;
            }

            $rules[] = [
                'id' => $id,
                'fingerprint' => is_string($fingerprint) && $fingerprint !== '' ? $fingerprint : null,
            ];
        }

        return [$rules, $errors];
    }
}
