<?php

declare(strict_types=1);

namespace Dgtlss\Warden\ValueObjects;

use Carbon\CarbonImmutable;
use InvalidArgumentException;

final readonly class AuditContext
{
    /**
     * @param list<string> $only
     * @param list<string> $skip
     */
    public function __construct(
        public string $profile = 'ci',
        public string $scope = 'production',
        public int $timeout = 300,
        public array $only = [],
        public array $skip = [],
        public ?CarbonImmutable $scannedAt = null,
    ) {
        if (!in_array($this->profile, ['ci', 'production', 'local'], true)) {
            throw new InvalidArgumentException(sprintf('Invalid audit profile "%s".', $this->profile));
        }

        if (!in_array($this->scope, ['production', 'all'], true)) {
            throw new InvalidArgumentException(sprintf('Invalid dependency scope "%s".', $this->scope));
        }

        if ($this->timeout < 1 || $this->timeout > 3600) {
            throw new InvalidArgumentException('Audit timeout must be between 1 and 3600 seconds.');
        }

        foreach ([...$this->only, ...$this->skip] as $audit) {
            if ($audit === '') {
                throw new InvalidArgumentException('Audit IDs cannot be empty.');
            }
        }
    }

    public function includes(string $auditId): bool
    {
        return !in_array($auditId, $this->skip, true)
            && ($this->only === [] || in_array($auditId, $this->only, true));
    }

    public function scanTime(): CarbonImmutable
    {
        return $this->scannedAt ?? CarbonImmutable::now();
    }
}
