<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

/**
 * A single security finding reported by banbo.
 *
 * Fields marked optional in the banbo JSON contract may be null / empty.
 */
final class Finding
{
    /**
     * @param string               $id          Stable finding identifier.
     * @param string               $title       Human-readable title.
     * @param string               $layer       One of: dns, network, transport, application, code.
     * @param Severity             $severity    Finding severity.
     * @param string               $asset       The asset the finding applies to.
     * @param string|null          $evidence    Raw evidence captured during the scan.
     * @param string|null          $description Longer description.
     * @param string|null          $remediation Suggested remediation.
     * @param list<string>         $references  Reference URLs / identifiers.
     * @param float|null           $cvss        CVSS score, if applicable.
     * @param list<string>         $compliance  Compliance frameworks touched.
     * @param string|null          $aiExplanation AI-generated explanation.
     * @param string|null          $aiRemediation AI-generated remediation.
     * @param string|null          $businessImpact Business impact summary.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly string $layer,
        public readonly Severity $severity,
        public readonly string $asset,
        public readonly ?string $evidence = null,
        public readonly ?string $description = null,
        public readonly ?string $remediation = null,
        public readonly array $references = [],
        public readonly ?float $cvss = null,
        public readonly array $compliance = [],
        public readonly ?string $aiExplanation = null,
        public readonly ?string $aiRemediation = null,
        public readonly ?string $businessImpact = null,
    ) {
    }

    /**
     * Build a Finding from one decoded JSON object.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: (string) ($data['id'] ?? ''),
            title: (string) ($data['title'] ?? ''),
            layer: (string) ($data['layer'] ?? ''),
            severity: Severity::fromJson((string) ($data['severity'] ?? 'info')),
            asset: (string) ($data['asset'] ?? ''),
            evidence: self::nullableString($data['evidence'] ?? null),
            description: self::nullableString($data['description'] ?? null),
            remediation: self::nullableString($data['remediation'] ?? null),
            references: self::stringList($data['references'] ?? null),
            cvss: isset($data['cvss']) ? (float) $data['cvss'] : null,
            compliance: self::stringList($data['compliance'] ?? null),
            aiExplanation: self::nullableString($data['ai_explanation'] ?? null),
            aiRemediation: self::nullableString($data['ai_remediation'] ?? null),
            businessImpact: self::nullableString($data['business_impact'] ?? null),
        );
    }

    private static function nullableString(mixed $value): ?string
    {
        return $value === null ? null : (string) $value;
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_map(static fn ($v): string => (string) $v, $value));
    }
}
