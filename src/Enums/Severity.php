<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Enums;

enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public function weight(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    public static function fromScannerValue(mixed $value, self $default = self::Medium): self
    {
        return is_string($value) ? (self::tryFrom(strtolower($value)) ?? $default) : $default;
    }
}
