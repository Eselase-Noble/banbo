<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

/**
 * Parsed result of a `banbo scan` or `banbo code` run (the JSON emitted on
 * stdout by `-o json`).
 */
final class ScanResult
{
    /**
     * @param list<Finding>     $findings
     * @param list<ModuleError> $errors
     */
    public function __construct(
        public readonly string $target,
        public readonly string $host,
        public readonly string $startedAt,
        public readonly int $durationMs,
        public readonly array $findings,
        public readonly Counts $summary,
        public readonly array $errors = [],
    ) {
    }

    /**
     * Parse a decoded JSON payload into a ScanResult.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $findings = [];
        foreach ((array) ($data['findings'] ?? []) as $finding) {
            if (is_array($finding)) {
                $findings[] = Finding::fromArray($finding);
            }
        }

        $errors = [];
        foreach ((array) ($data['errors'] ?? []) as $error) {
            if (is_array($error)) {
                $errors[] = ModuleError::fromArray($error);
            }
        }

        $summary = isset($data['summary']) && is_array($data['summary'])
            ? Counts::fromArray($data['summary'])
            : new Counts();

        return new self(
            target: (string) ($data['target'] ?? ''),
            host: (string) ($data['host'] ?? ''),
            startedAt: (string) ($data['started_at'] ?? ''),
            durationMs: (int) ($data['duration_ms'] ?? 0),
            findings: $findings,
            summary: $summary,
            errors: $errors,
        );
    }

    /**
     * Parse a raw JSON string (banbo stdout) into a ScanResult.
     *
     * @throws BanboException if the JSON cannot be decoded into an object.
     */
    public static function fromJson(string $json): self
    {
        try {
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new BanboException(
                'failed to decode banbo JSON output: ' . $e->getMessage(),
                0,
                $e
            );
        }

        if (!is_array($data)) {
            throw new BanboException('banbo JSON output was not an object');
        }

        return self::fromArray($data);
    }

    /**
     * True when the scan produced at least one high or critical finding.
     */
    public function hasHighOrCritical(): bool
    {
        return $this->summary->high > 0 || $this->summary->critical > 0;
    }

    /**
     * Findings filtered to a single severity.
     *
     * @return list<Finding>
     */
    public function findingsBySeverity(Severity $severity): array
    {
        return array_values(array_filter(
            $this->findings,
            static fn (Finding $f): bool => $f->severity === $severity
        ));
    }
}
