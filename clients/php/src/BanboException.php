<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

use RuntimeException;

/**
 * Raised for any error produced by the banbo wrapper: platform detection,
 * binary download/extraction, process execution failures, non-OK exit codes,
 * and malformed JSON output.
 */
final class BanboException extends RuntimeException
{
    /**
     * Create an exception for a process that exited with an error code
     * (anything other than 0/1/2, which banbo treats as "ran OK").
     */
    public static function fromExit(int $exitCode, string $stderr): self
    {
        $stderr = trim($stderr);
        $detail = $stderr === '' ? '' : ': ' . $stderr;

        return new self(
            sprintf('banbo exited with code %d%s', $exitCode, $detail)
        );
    }
}
