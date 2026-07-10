<?php

declare(strict_types=1);

namespace Dgtlss\Warden\ValueObjects;

use Carbon\CarbonImmutable;
use Composer\InstalledVersions;
use Dgtlss\Warden\Enums\Severity;
use JsonSerializable;

final readonly class AuditReport implements JsonSerializable
{
    /**
     * @param list<AuditResult> $audits
     * @param list<Finding> $ignoredFindings
     * @param list<AuditError> $configurationErrors
     */
    public function __construct(
        public AuditContext $context,
        public array $audits,
        public array $ignoredFindings = [],
        public array $configurationErrors = [],
        public ?CarbonImmutable $scannedAt = null,
    ) {
    }

    /** @return list<Finding> */
    public function findings(): array
    {
        $findings = [];
        foreach ($this->audits as $audit) {
            array_push($findings, ...$audit->findings);
        }

        usort($findings, static function (Finding $left, Finding $right): int {
            $severity = $right->severity->weight() <=> $left->severity->weight();
            if ($severity !== 0) {
                return $severity;
            }

            return [$left->source, $left->id, $left->fingerprint()]
                <=> [$right->source, $right->id, $right->fingerprint()];
        });

        return $findings;
    }

    /** @return list<AuditError> */
    public function errors(): array
    {
        $errors = $this->configurationErrors;
        foreach ($this->audits as $audit) {
            array_push($errors, ...$audit->errors);
        }

        return $errors;
    }

    public function exitCode(string $failOn): int
    {
        if ($this->errors() !== []) {
            return 2;
        }

        if ($failOn === 'never') {
            return 0;
        }

        $threshold = Severity::from($failOn)->weight();
        foreach ($this->findings() as $finding) {
            if ($finding->blocking && $finding->severity->weight() >= $threshold) {
                return 1;
            }
        }

        return 0;
    }

    /**
     * @param list<AuditResult> $audits
     * @param list<Finding> $ignoredFindings
     * @param list<AuditError> $configurationErrors
     */
    public function withFilteredFindings(array $audits, array $ignoredFindings, array $configurationErrors): self
    {
        return new self($this->context, $audits, $ignoredFindings, $configurationErrors, $this->scannedAt);
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        $blocking = 0;
        foreach ($this->findings() as $finding) {
            $counts[$finding->severity->value]++;
            $blocking += $finding->blocking ? 1 : 0;
        }

        return [
            'schema_version' => '2.0.0',
            'warden_version' => $this->wardenVersion(),
            'run' => [
                'status' => $this->errors() === [] ? 'completed' : 'failed',
                'profile' => $this->context->profile,
                'scope' => $this->context->scope,
                'scanned_at' => ($this->scannedAt ?? CarbonImmutable::now())->toISOString(),
            ],
            'summary' => [
                'total' => count($this->findings()),
                'blocking' => $blocking,
                'advisory' => count($this->findings()) - $blocking,
                'ignored' => count($this->ignoredFindings),
                'errors' => count($this->errors()),
                'severity' => $counts,
            ],
            'audits' => $this->audits,
            'findings' => $this->findings(),
            'ignored_findings' => $this->ignoredFindings,
            'errors' => $this->errors(),
        ];
    }

    private function wardenVersion(): string
    {
        if (InstalledVersions::isInstalled('dgtlss/warden')) {
            return InstalledVersions::getPrettyVersion('dgtlss/warden') ?? 'unknown';
        }

        $root = InstalledVersions::getRootPackage();

        return $root['pretty_version'];
    }
}
