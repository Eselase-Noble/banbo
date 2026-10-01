<?php

declare(strict_types=1);

namespace EselaseNoble\Banbo;

use PharData;
use ZipArchive;

/**
 * Resolves the banbo executable for the current host and runs it.
 *
 * Resolution precedence:
 *   1. The BANBO_BINARY environment variable, if it points at an existing file.
 *   2. A previously-extracted copy in the per-version cache directory.
 *   3. Download the release archive from GitHub, verify its sha256 against the
 *      attached checksums.txt (best effort), extract it, chmod +x, and cache it.
 *
 * The binary is downloaded at most once per version; subsequent calls reuse the
 * cached copy.
 */
final class BinaryResolver
{
    public const OWNER = 'Eselase-Noble';
    public const REPO = 'banbo';

    /** Release version this wrapper pins to (git tag v{VERSION}). */
    public const VERSION = '0.1.2';

    /** @var array<string, string> Memoized resolved paths keyed by version. */
    private static array $resolved = [];

    /**
     * Absolute path to a runnable banbo executable, downloading/extracting on
     * first use.
     *
     * @throws BanboException on unsupported platform or download/extract failure.
     */
    public static function resolve(string $version = self::VERSION): string
    {
        $override = getenv('BANBO_BINARY');
        if (is_string($override) && trim($override) !== '') {
            if (!is_file($override)) {
                throw new BanboException(sprintf(
                    'BANBO_BINARY is set to "%s" but that file does not exist.',
                    $override
                ));
            }

            return $override;
        }

        if (isset(self::$resolved[$version]) && is_file(self::$resolved[$version])) {
            return self::$resolved[$version];
        }

        $target = self::detectTarget();
        $cacheDir = self::cacheDir($version);
        $binaryPath = $cacheDir . DIRECTORY_SEPARATOR . $target['exe'];

        if (is_file($binaryPath)) {
            self::ensureExecutable($binaryPath);

            return self::$resolved[$version] = $binaryPath;
        }

        self::download($version, $target, $cacheDir, $binaryPath);
        self::ensureExecutable($binaryPath);

        return self::$resolved[$version] = $binaryPath;
    }

    /**
     * Run the resolved banbo binary with the given argument list.
     *
     * Exit codes 0/1/2 are returned normally; any other code throws.
     *
     * @param list<string>          $args CLI arguments (without the binary itself).
     * @param array<string, string> $env  Extra environment variables.
     *
     * @throws BanboException on spawn failure or an error exit code.
     */
    public static function exec(array $args, array $env = [], string $version = self::VERSION): Result
    {
        $binary = self::resolve($version);

        return self::run($binary, $args, $env);
    }

    /**
     * Detect the current host's release tokens.
     *
     * @return array{os: string, arch: string, ext: string, exe: string}
     *
     * @throws BanboException on an unsupported platform/architecture.
     */
    public static function detectTarget(): array
    {
        $os = match (PHP_OS_FAMILY) {
            'Linux' => 'linux',
            'Darwin' => 'darwin',
            'Windows' => 'windows',
            default => null,
        };

        $machine = strtolower(trim((string) php_uname('m')));
        $arch = match ($machine) {
            'x86_64', 'amd64' => 'amd64',
            'arm64', 'aarch64' => 'arm64',
            default => null,
        };

        if ($os === null || $arch === null) {
            throw new BanboException(sprintf(
                'banbo: unsupported platform "%s/%s". Prebuilt binaries exist for '
                . 'linux, darwin and windows on amd64/arm64. Set BANBO_BINARY to a '
                . 'locally built binary to use an unsupported platform.',
                PHP_OS_FAMILY,
                $machine
            ));
        }

        return [
            'os' => $os,
            'arch' => $arch,
            'ext' => $os === 'windows' ? 'zip' : 'tar.gz',
            'exe' => $os === 'windows' ? 'banbo.exe' : 'banbo',
        ];
    }

    /** Base archive name, e.g. "banbo_darwin_arm64". */
    public static function archiveBaseName(array $target): string
    {
        return sprintf('%s_%s_%s', self::REPO, $target['os'], $target['arch']);
    }

    /** Full download URL for the release archive. */
    public static function archiveUrl(string $version, array $target): string
    {
        return sprintf(
            'https://github.com/%s/%s/releases/download/v%s/%s.%s',
            self::OWNER,
            self::REPO,
            $version,
            self::archiveBaseName($target),
            $target['ext']
        );
    }

    /** Full download URL for the release checksums file. */
    public static function checksumsUrl(string $version): string
    {
        return sprintf(
            'https://github.com/%s/%s/releases/download/v%s/checksums.txt',
            self::OWNER,
            self::REPO,
            $version
        );
    }

    /** Per-version cache directory (created on demand). */
    public static function cacheDir(string $version = self::VERSION): string
    {
        return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'banbo' . DIRECTORY_SEPARATOR . $version;
    }

    /**
     * Download, verify and extract the release archive into $cacheDir, leaving a
     * runnable binary at $binaryPath.
     *
     * @param array{os: string, arch: string, ext: string, exe: string} $target
     *
     * @throws BanboException
     */
    private static function download(string $version, array $target, string $cacheDir, string $binaryPath): void
    {
        self::makeDir($cacheDir);

        $archiveUrl = self::archiveUrl($version, $target);
        $archiveData = self::httpGet($archiveUrl);
        if ($archiveData === null) {
            throw new BanboException(sprintf(
                'failed to download banbo release archive from %s',
                $archiveUrl
            ));
        }

        self::verifyChecksum($version, $target, $archiveData);

        // Extract into a temp staging dir to avoid leaving partial files in the
        // cache on failure; use a unique archive filename to allow concurrency.
        $staging = $cacheDir . DIRECTORY_SEPARATOR . '.extract-' . bin2hex(random_bytes(6));
        self::makeDir($staging);

        $archiveFile = $staging . DIRECTORY_SEPARATOR
            . self::archiveBaseName($target) . '.' . $target['ext'];

        if (file_put_contents($archiveFile, $archiveData) === false) {
            throw new BanboException('failed to write banbo archive to disk');
        }

        try {
            if ($target['ext'] === 'zip') {
                self::extractZip($archiveFile, $staging);
            } else {
                self::extractTarGz($archiveFile, $staging);
            }

            $extracted = self::findExecutable($staging, $target['exe']);
            if ($extracted === null) {
                throw new BanboException(sprintf(
                    'banbo executable "%s" not found inside archive %s',
                    $target['exe'],
                    $archiveUrl
                ));
            }

            // Move into place (copy+unlink is portable across filesystems).
            if (!@rename($extracted, $binaryPath)) {
                if (!@copy($extracted, $binaryPath)) {
                    throw new BanboException('failed to install banbo binary into cache');
                }
            }
        } finally {
            self::removeDir($staging);
        }
    }

    /**
     * Best-effort sha256 verification against the release checksums.txt.
     *
     * If checksums.txt cannot be fetched or does not list this archive we skip
     * verification rather than failing the install; a mismatch, however, always
     * throws.
     *
     * @param array{os: string, arch: string, ext: string, exe: string} $target
     *
     * @throws BanboException on a checksum mismatch.
     */
    private static function verifyChecksum(string $version, array $target, string $archiveData): void
    {
        $checksums = self::httpGet(self::checksumsUrl($version));
        if ($checksums === null) {
            return; // checksums.txt unavailable; skip (best effort).
        }

        $archiveName = self::archiveBaseName($target) . '.' . $target['ext'];
        $expected = null;

        foreach (preg_split('/\R/', $checksums) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            // Format: "<sha256>  <filename>" (two spaces, GNU coreutils style).
            $parts = preg_split('/\s+/', $line);
            if ($parts === false || count($parts) < 2) {
                continue;
            }

            [$hash, $name] = [$parts[0], basename($parts[count($parts) - 1])];
            if ($name === $archiveName) {
                $expected = strtolower($hash);
                break;
            }
        }

        if ($expected === null) {
            return; // archive not listed; skip (best effort).
        }

        $actual = hash('sha256', $archiveData);
        if (!hash_equals($expected, $actual)) {
            throw new BanboException(sprintf(
                'banbo archive checksum mismatch for %s: expected %s, got %s',
                $archiveName,
                $expected,
                $actual
            ));
        }
    }

    /**
     * Extract a .tar.gz archive using PharData.
     *
     * @throws BanboException if the phar extension is unavailable or extraction fails.
     */
    private static function extractTarGz(string $archiveFile, string $destination): void
    {
        if (!class_exists(PharData::class)) {
            throw new BanboException(
                'the "phar" extension is required to extract the banbo .tar.gz archive'
            );
        }

        try {
            // Decompress .tar.gz -> .tar, then extract the tar.
            $gz = new PharData($archiveFile);
            $tar = $gz->decompress(); // produces a sibling .tar file
            $tar->extractTo($destination, null, true);

            // Clean up the intermediate .tar that decompress() creates.
            $tarPath = $tar->getPath();
            unset($gz, $tar);
            if (is_file($tarPath)) {
                @unlink($tarPath);
            }
        } catch (\Throwable $e) {
            throw new BanboException(
                'failed to extract banbo .tar.gz archive: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Extract a .zip archive using ZipArchive.
     *
     * @throws BanboException if the zip extension is unavailable or extraction fails.
     */
    private static function extractZip(string $archiveFile, string $destination): void
    {
        if (!class_exists(ZipArchive::class)) {
            throw new BanboException(
                'the "zip" extension is required to extract the banbo .zip archive'
            );
        }

        $zip = new ZipArchive();
        $opened = $zip->open($archiveFile);
        if ($opened !== true) {
            throw new BanboException(sprintf(
                'failed to open banbo .zip archive (ZipArchive error %s)',
                (string) $opened
            ));
        }

        try {
            if (!$zip->extractTo($destination)) {
                throw new BanboException('failed to extract banbo .zip archive');
            }
        } finally {
            $zip->close();
        }
    }

    /**
     * Recursively locate the named executable inside an extracted tree.
     */
    private static function findExecutable(string $dir, string $exe): ?string
    {
        $direct = $dir . DIRECTORY_SEPARATOR . $exe;
        if (is_file($direct)) {
            return $direct;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if ($file->isFile() && $file->getFilename() === $exe) {
                return $file->getPathname();
            }
        }

        return null;
    }

    /**
     * Run the binary via proc_open, capturing stdout and stderr.
     *
     * @param list<string>          $args
     * @param array<string, string> $env
     *
     * @throws BanboException
     */
    private static function run(string $binary, array $args, array $env): Result
    {
        $command = array_merge([$binary], $args);

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        // Inherit the current environment and overlay any caller-supplied vars.
        $environment = null;
        if ($env !== []) {
            $environment = array_merge(self::currentEnv(), $env);
        }

        $pipes = [];
        $process = @proc_open($command, $descriptors, $pipes, null, $environment);

        if (!is_resource($process)) {
            throw new BanboException(sprintf(
                'failed to start banbo process: %s',
                $binary
            ));
        }

        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        $result = new Result(
            $exitCode,
            $stdout === false ? '' : $stdout,
            $stderr === false ? '' : $stderr,
        );

        if (!$result->ok()) {
            throw BanboException::fromExit($result->exitCode, $result->stderr);
        }

        return $result;
    }

    /**
     * Snapshot of the current process environment as a flat map.
     *
     * @return array<string, string>
     */
    private static function currentEnv(): array
    {
        $env = [];
        foreach ($_ENV as $key => $value) {
            $env[(string) $key] = (string) $value;
        }

        // $_ENV may be empty depending on variables_order; fall back to getenv().
        if ($env === [] && function_exists('getenv')) {
            $all = getenv();
            if (is_array($all)) {
                foreach ($all as $key => $value) {
                    $env[(string) $key] = (string) $value;
                }
            }
        }

        return $env;
    }

    private static function ensureExecutable(string $path): void
    {
        if (PHP_OS_FAMILY !== 'Windows' && !is_executable($path)) {
            @chmod($path, 0o755);
        }
    }

    private static function makeDir(string $dir): void
    {
        if (is_dir($dir)) {
            return;
        }

        if (!@mkdir($dir, 0o755, true) && !is_dir($dir)) {
            throw new BanboException(sprintf('failed to create directory "%s"', $dir));
        }
    }

    private static function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if ($file->isDir()) {
                @rmdir($file->getPathname());
            } else {
                @unlink($file->getPathname());
            }
        }

        @rmdir($dir);
    }

    /**
     * Fetch a URL (following redirects, as GitHub release downloads 302 to a CDN).
     * Returns the body, or null on any transport-level failure.
     */
    private static function httpGet(string $url): ?string
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch === false) {
                return null;
            }

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_CONNECTTIMEOUT => 30,
                CURLOPT_TIMEOUT => 300,
                CURLOPT_USERAGENT => 'banbo-php/' . self::VERSION,
                CURLOPT_FAILONERROR => true,
            ]);

            $body = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($body === false || $status >= 400) {
                return null;
            }

            return (string) $body;
        }

        // Fallback to the stream wrapper (requires allow_url_fopen).
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'follow_location' => 1,
                'max_redirects' => 5,
                'timeout' => 300,
                'header' => 'User-Agent: banbo-php/' . self::VERSION . "\r\n",
                'ignore_errors' => false,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);

        $body = @file_get_contents($url, false, $context);

        return $body === false ? null : $body;
    }
}
