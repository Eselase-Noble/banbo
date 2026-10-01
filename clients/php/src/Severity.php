<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

/**
 * Severity of a {@see Finding}, ordered from least to most serious.
 *
 * Backed by the lowercase JSON tokens emitted by banbo (e.g. "high").
 */
enum Severity: string
{
    case Info = 'info';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    /**
     * Parse a severity from its JSON token, case-insensitively.
     *
     * @throws BanboException if the value is not a known severity.
     */
    public static function fromJson(string $value): self
    {
        $severity = self::tryFrom(strtolower(trim($value)));

        if ($severity === null) {
            throw new BanboException(sprintf('unknown severity "%s"', $value));
        }

        return $severity;
    }

    /**
     * Rank from 0 (info) to 4 (critical); useful for sorting/comparison.
     */
    public function rank(): int
    {
        return match ($this) {
            self::Info => 0,
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }
}
