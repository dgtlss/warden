<?php

namespace Dgtlss\Warden\Enums;

enum Severity: string
{
    case CRITICAL = 'critical';
    case HIGH = 'high';
    case MEDIUM = 'medium';
    case MODERATE = 'moderate';
    case LOW = 'low';
    case ERROR = 'error';
    case UNKNOWN = 'unknown';

    /**
     * Get the display name for the severity level.
     */
    public function label(): string
    {
        return match($this) {
            self::CRITICAL => 'Critical',
            self::HIGH => 'High',
            self::MEDIUM => 'Medium',
            self::MODERATE => 'Moderate',
            self::LOW => 'Low',
            self::ERROR => 'Error',
            self::UNKNOWN => 'Unknown',
        };
    }

    /**
     * Get the priority/weight for sorting (higher is more severe).
     */
    public function priority(): int
    {
        return match($this) {
            self::CRITICAL => 5,
            self::HIGH => 4,
            self::MEDIUM, self::MODERATE => 3,
            self::LOW => 2,
            self::ERROR => 1,
            self::UNKNOWN => 0,
        };
    }

    /**
     * Get the color code for this severity level.
     */
    public function color(): string
    {
        return match($this) {
            self::CRITICAL => '#FF0000', // Red
            self::HIGH => '#FF6B6B',     // Light Red
            self::MEDIUM, self::MODERATE => '#FFA500', // Orange
            self::LOW => '#FFD700',      // Gold
            self::ERROR => '#DC143C',    // Crimson
            self::UNKNOWN => '#808080',  // Gray
        };
    }

    /**
     * Convert to GitHub Actions annotation level.
     */
    public function toGitHubLevel(): string
    {
        return match($this) {
            self::CRITICAL, self::HIGH => 'error',
            self::MEDIUM, self::MODERATE => 'warning',
            default => 'notice',
        };
    }

    /**
     * Create from string value (case-insensitive).
     */
    public static function fromString(string $value): self
    {
        $normalized = strtolower(trim($value));

        return match($normalized) {
            'critical' => self::CRITICAL,
            'high' => self::HIGH,
            'medium' => self::MEDIUM,
            'moderate' => self::MODERATE,
            'low' => self::LOW,
            'error' => self::ERROR,
            default => self::UNKNOWN,
        };
    }

    /**
     * Get all severity levels sorted by priority (most severe first).
     *
     * @return array<self>
     */
    public static function sortedByPriority(): array
    {
        $cases = self::cases();

        usort($cases, fn(self $a, self $b) => $b->priority() <=> $a->priority());

        return $cases;
    }
}
