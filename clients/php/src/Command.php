<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

/**
 * Fluent builder for a single banbo invocation (`scan` or `code`).
 *
 * Instances are produced by {@see Banbo::scan()} and {@see Banbo::code()}. Call
 * the chainable option methods, then terminate with {@see run()} (parsed
 * {@see ScanResult}) or {@see runRaw()} (a raw {@see Result}).
 *
 * All option setters mutate and return $this.
 */
final class Command
{
    public const SCAN = 'scan';
    public const CODE = 'code';

    /** @var 'scan'|'code' */
    private string $subcommand;

    private string $argument;

    private bool $authorized = false;
    private bool $full = false;
    private bool $noAi = false;
    private bool $active = false;
    private bool $noColor = true;

    /** @var list<string> */
    private array $ports = [];

    private ?string $timeout = null;

    /** @var array<string, string> */
    private array $env = [];

    private string $version;

    /**
     * @param 'scan'|'code' $subcommand
     */
    private function __construct(string $subcommand, string $argument, string $version)
    {
        $this->subcommand = $subcommand;
        $this->argument = $argument;
        $this->version = $version;
    }

    /** Build a `banbo scan <target>` command. */
    public static function scan(string $target, string $version = BinaryResolver::VERSION): self
    {
        return new self(self::SCAN, $target, $version);
    }

    /** Build a `banbo code [path]` command. */
    public static function code(string $path = '.', string $version = BinaryResolver::VERSION): self
    {
        return new self(self::CODE, $path, $version);
    }

    /**
     * Confirm you are authorized to scan the target (adds `-y`).
     * Required for network scans against hosts you do not own.
     */
    public function authorized(bool $authorized = true): self
    {
        $this->authorized = $authorized;

        return $this;
    }

    /** Request a full source-code review (`--full`); only meaningful for `code`. */
    public function full(bool $full = true): self
    {
        $this->full = $full;

        return $this;
    }

    /** Disable the AI explanation/remediation layer (`--no-ai`). */
    public function noAi(bool $noAi = true): self
    {
        $this->noAi = $noAi;

        return $this;
    }

    /** Enable active checks (`--active`); only meaningful for `scan`. */
    public function active(bool $active = true): self
    {
        $this->active = $active;

        return $this;
    }

    /**
     * Toggle ANSI colour in banbo's output. Defaults to off (`--no-color`) so
     * captured output stays clean; pass false to let banbo colourize.
     */
    public function noColor(bool $noColor = true): self
    {
        $this->noColor = $noColor;

        return $this;
    }

    /**
     * Restrict the port set (`--ports p1,p2`); only meaningful for `scan`.
     *
     * Accepts a comma-separated string or a list of ports (int or string).
     *
     * @param string|list<int|string> $ports
     */
    public function ports(string|array $ports): self
    {
        if (is_string($ports)) {
            $ports = array_filter(array_map('trim', explode(',', $ports)), static fn ($p) => $p !== '');
        }

        $this->ports = array_values(array_map(static fn ($p): string => (string) $p, $ports));

        return $this;
    }

    /**
     * Per-module timeout (`--timeout 5s`); only meaningful for `scan`.
     * Pass a Go-style duration string such as "5s", "500ms" or "1m".
     */
    public function timeout(string $timeout): self
    {
        $this->timeout = $timeout;

        return $this;
    }

    /**
     * Add/override an environment variable passed to the banbo process.
     */
    public function withEnv(string $name, string $value): self
    {
        $this->env[$name] = $value;

        return $this;
    }

    /**
     * Assemble the full CLI argument list (without the binary path).
     *
     * @return list<string>
     */
    public function toArgs(): array
    {
        $args = [$this->subcommand, $this->argument, '-o', 'json'];

        if ($this->authorized) {
            $args[] = '-y';
        }

        if ($this->full) {
            $args[] = '--full';
        }

        if ($this->noAi) {
            $args[] = '--no-ai';
        }

        if ($this->active) {
            $args[] = '--active';
        }

        if ($this->noColor) {
            $args[] = '--no-color';
        }

        if ($this->ports !== []) {
            $args[] = '--ports';
            $args[] = implode(',', $this->ports);
        }

        if ($this->timeout !== null) {
            $args[] = '--timeout';
            $args[] = $this->timeout;
        }

        return $args;
    }

    /**
     * Execute banbo and return the parsed {@see ScanResult}.
     *
     * @throws BanboException on an error exit code or malformed JSON.
     */
    public function run(): ScanResult
    {
        return $this->runRaw()->toScanResult();
    }

    /**
     * Execute banbo and return the raw {@see Result} (exit code + streams).
     *
     * @throws BanboException on an error exit code.
     */
    public function runRaw(): Result
    {
        return BinaryResolver::exec($this->toArgs(), $this->env, $this->version);
    }
}
