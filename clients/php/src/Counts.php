<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

/**
 * Severity breakdown of a scan, taken from the JSON "summary" object.
 */
final class Counts
{
    public function __construct(
        public readonly int $critical = 0,
        public readonly int $high = 0,
        public readonly int $medium = 0,
        public readonly int $low = 0,
        public readonly int $info = 0,
        public readonly int $total = 0,
    ) {
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            critical: (int) ($data['critical'] ?? 0),
            high: (int) ($data['high'] ?? 0),
            medium: (int) ($data['medium'] ?? 0),
            low: (int) ($data['low'] ?? 0),
            info: (int) ($data['info'] ?? 0),
            total: (int) ($data['total'] ?? 0),
        );
    }
}
