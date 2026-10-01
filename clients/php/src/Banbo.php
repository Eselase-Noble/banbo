<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

/**
 * Entry point for the banbo PHP wrapper.
 *
 * This class does not reimplement scanning: it resolves (downloading on first
 * use) the prebuilt banbo CLI binary and executes it, parsing the JSON output.
 *
 * Typical usage:
 *
 *     use EselaseNoble\Banbo\Banbo;
 *
 *     $result = Banbo::scan('example.com')
 *         ->authorized()
 *         ->ports('80,443')
 *         ->timeout('5s')
 *         ->run();
 *
 *     foreach ($result->findings as $finding) {
 *         echo $finding->severity->value, ' ', $finding->title, PHP_EOL;
 *     }
 */
final class Banbo
{
    /**
     * Start building a `banbo scan <target>` command.
     *
     * @param string $target host or URL to scan.
     */
    public static function scan(string $target): Command
    {
        return Command::scan($target);
    }

    /**
     * Start building a `banbo code [path]` source-code review command.
     *
     * @param string $path directory or file to review (defaults to the cwd).
     */
    public static function code(string $path = '.'): Command
    {
        return Command::code($path);
    }

    /**
     * Run the banbo binary directly with an arbitrary argument list.
     *
     * Exit codes 0/1/2 are treated as "ran OK"; any other code throws.
     *
     * @param list<string>          $args CLI arguments (without the binary itself).
     * @param array<string, string> $env  Extra environment variables.
     *
     * @throws BanboException on spawn failure or an error exit code.
     */
    public static function exec(array $args, array $env = []): Result
    {
        return BinaryResolver::exec($args, $env);
    }

    /**
     * Return banbo's own version string (`banbo version`).
     */
    public static function version(): string
    {
        return trim(self::exec(['version'])->stdout);
    }

    /**
     * Absolute path to the resolved banbo binary (downloading on first use).
     */
    public static function binaryPath(): string
    {
        return BinaryResolver::resolve();
    }
}
