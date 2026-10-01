<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

/**
 * A non-fatal error reported by an individual banbo scan module.
 *
 * These appear in the optional top-level "errors" array; the scan itself
 * still completes and returns findings for the modules that succeeded.
 */
final class ModuleError
{
    public function __construct(
        public readonly string $module,
        public readonly string $error,
    ) {
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            module: (string) ($data['module'] ?? ''),
            error: (string) ($data['error'] ?? ''),
        );
    }
}
