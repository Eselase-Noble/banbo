<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

/**
 * Raw result of running the banbo binary: exit code plus captured streams.
 *
 * An exit code of 0, 1 or 2 means banbo "ran OK" (0 = clean/info,
 * 1 = low/medium, 2 = high/critical). Any other code is an error.
 */
final class Result
{
    public function __construct(
        public readonly int $exitCode,
        public readonly string $stdout,
        public readonly string $stderr,
    ) {
    }

    /**
     * True when banbo completed a scan (exit 0/1/2), as opposed to failing.
     */
    public function ok(): bool
    {
        return $this->exitCode === 0 || $this->exitCode === 1 || $this->exitCode === 2;
    }

    /**
     * Decode stdout as a {@see ScanResult}.
     *
     * @throws BanboException on malformed JSON.
     */
    public function toScanResult(): ScanResult
    {
        return ScanResult::fromJson($this->stdout);
    }
}
