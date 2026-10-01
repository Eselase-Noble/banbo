package io.github.eselasenoble.banbo;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Resolves the banbo executable for the current platform.
 *
 * <p>Resolution order:</p>
 * <ol>
 *   <li>If the {@code BANBO_BINARY} environment variable is set, that path is used
 *       directly and nothing is downloaded.</li>
 *   <li>Otherwise the correct release archive is downloaded once into a per-user
 *       cache directory ({@code ~/.cache/banbo/&lt;version&gt;/} or the OS equivalent),
 *       extracted, made executable, and reused on subsequent calls.</li>
 * </ol>
 *
 * <p>This class is thread-safe: concurrent resolutions for the same version are
 * coordinated so the archive is downloaded and extracted only once.</p>
 */
public final class BinaryResolver {

    /** The banbo version this client targets; also the release tag suffix. */
    public static final String VERSION = "0.1.3";

    private static final String ENV_OVERRIDE = "BANBO_BINARY";
    private static final String RELEASE_URL_TEMPLATE =
            "https://github.com/Eselase-Noble/banbo/releases/download/v%s/%s";

    /** Guards per-version resolution so a given version is materialized only once. */
    private static final ConcurrentHashMap<String, Object> VERSION_LOCKS = new ConcurrentHashMap<>();

    /** Successfully-executable exit codes per the banbo contract: findings are expected. */
    private static final Set<Integer> OK_EXIT_CODES = Set.of(0, 1, 2);

    private final String version;

    public BinaryResolver() {
        this(VERSION);
    }

    public BinaryResolver(String version) {
        this.version = version;
    }

    /** @return {@code true} if the given exit code means banbo ran successfully. */
    public static boolean isOkExitCode(int exitCode) {
        return OK_EXIT_CODES.contains(exitCode);
    }

    /**
     * Resolves the banbo executable, downloading and extracting it if necessary.
     *
     * @return an absolute path to the banbo executable
     * @throws BanboException if resolution fails
     */
    public Path resolve() {
        String override = System.getenv(ENV_OVERRIDE);
        if (override != null && !override.trim().isEmpty()) {
            Path p = Paths.get(override.trim()).toAbsolutePath();
            if (!Files.isRegularFile(p)) {
                throw new BanboException(ENV_OVERRIDE + " is set to '" + p
                        + "' but no file exists there.");
            }
            return p;
        }

        Platform platform = Platform.detect();
        Path exePath = cacheDir().resolve(platform.executableName());

        if (Files.isRegularFile(exePath)) {
            return exePath;
        }

        // Serialize download+extract per version across threads.
        Object lock = VERSION_LOCKS.computeIfAbsent(version, v -> new Object());
        synchronized (lock) {
            if (Files.isRegularFile(exePath)) {
                return exePath;
            }
            downloadAndExtract(platform, exePath);
            return exePath;
        }
    }

    /**
     * Executes the banbo binary with the given arguments.
     *
     * @param args arguments passed to banbo (not including the binary path itself)
     * @return the raw exit code, stdout, and stderr
     * @throws BanboException if the binary cannot be launched, is interrupted, or exits
     *                        with a code outside {0, 1, 2}
     */
    public BanboResult exec(String... args) {
        Path binary = resolve();

        java.util.List<String> command = new java.util.ArrayList<>();
        command.add(binary.toString());
        for (String a : args) {
            command.add(a);
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            throw new BanboException("Failed to launch banbo: " + e.getMessage(), e);
        }

        // Drain stdout and stderr concurrently to avoid deadlocking on full pipe buffers.
        StreamCollector outCollector = new StreamCollector(process.getInputStream());
        StreamCollector errCollector = new StreamCollector(process.getErrorStream());
        Thread outThread = new Thread(outCollector, "banbo-stdout");
        Thread errThread = new Thread(errCollector, "banbo-stderr");
        outThread.start();
        errThread.start();

        int exitCode;
        try {
            exitCode = process.waitFor();
            outThread.join();
            errThread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new BanboException("Interrupted while waiting for banbo to finish.", e);
        }

        if (outCollector.error != null) {
            throw new BanboException("Failed to read banbo stdout.", outCollector.error);
        }
        if (errCollector.error != null) {
            throw new BanboException("Failed to read banbo stderr.", errCollector.error);
        }

        String stdout = outCollector.content();
        String stderr = errCollector.content();

        if (!isOkExitCode(exitCode)) {
            throw new BanboException("banbo exited with code " + exitCode
                    + " (execution error). stderr: " + stderr.trim());
        }

        return new BanboResult(exitCode, stdout, stderr);
    }

    // --- download / extract -------------------------------------------------

    private void downloadAndExtract(Platform platform, Path exePath) {
        Path dir = cacheDir();
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new BanboException("Failed to create cache directory " + dir, e);
        }

        String archiveName = platform.archiveName();
        String url = String.format(RELEASE_URL_TEMPLATE, version, archiveName);

        // Download into a temp file next to the target, then extract and atomically
        // move the executable into place so partial downloads are never cached.
        Path tmpArchive;
        try {
            tmpArchive = Files.createTempFile(dir, "banbo-download-", "." + platform.ext());
        } catch (IOException e) {
            throw new BanboException("Failed to create temp file in " + dir, e);
        }

        try {
            download(url, tmpArchive);

            Path extractedExe;
            if (platform.ext().equals("zip")) {
                extractedExe = extractZip(tmpArchive, dir, platform.executableName());
            } else {
                extractedExe = extractTarGz(tmpArchive, dir, platform.executableName());
            }

            makeExecutable(extractedExe);

            if (!extractedExe.equals(exePath)) {
                Files.move(extractedExe, exePath,
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                makeExecutable(exePath);
            }
        } catch (IOException e) {
            throw new BanboException("Failed to download/extract banbo from " + url
                    + ": " + e.getMessage(), e);
        } finally {
            try {
                Files.deleteIfExists(tmpArchive);
            } catch (IOException ignored) {
                // best effort cleanup
            }
        }

        if (!Files.isRegularFile(exePath)) {
            throw new BanboException("banbo executable not found after extraction at " + exePath);
        }
    }

    private static void download(String urlStr, Path target) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(30_000);
        conn.setReadTimeout(120_000);
        conn.setRequestProperty("User-Agent", "banbo-java-client/" + VERSION);
        conn.setRequestProperty("Accept", "application/octet-stream");

        int code = conn.getResponseCode();
        // Manually follow a cross-protocol/host redirect (e.g. github.com -> objects.githubusercontent.com)
        // which HttpURLConnection will not auto-follow for https->https in all JDKs.
        if (code >= 300 && code < 400) {
            String location = conn.getHeaderField("Location");
            conn.disconnect();
            if (location == null) {
                throw new IOException("Redirect with no Location header for " + urlStr);
            }
            download(location, target);
            return;
        }
        if (code != HttpURLConnection.HTTP_OK) {
            conn.disconnect();
            throw new IOException("HTTP " + code + " downloading " + urlStr);
        }

        try (InputStream in = conn.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            conn.disconnect();
        }
    }

    private static Path extractZip(Path archive, Path destDir, String exeName) throws IOException {
        Path out = destDir.resolve(exeName);
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(archive))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                String name = baseName(entry.getName());
                if (name.equals(exeName)) {
                    Files.copy(zis, out, StandardCopyOption.REPLACE_EXISTING);
                    return out;
                }
            }
        }
        throw new IOException("Executable '" + exeName + "' not found inside zip archive.");
    }

    private static Path extractTarGz(Path archive, Path destDir, String exeName) throws IOException {
        Path out = destDir.resolve(exeName);
        try (InputStream fis = Files.newInputStream(archive);
             GZIPInputStream gzis = new GZIPInputStream(fis)) {
            boolean found = TarReader.forFirstMatch(gzis, exeName, (body, size) ->
                    Files.copy(body, out, StandardCopyOption.REPLACE_EXISTING));
            if (found) {
                return out;
            }
        }
        throw new IOException("Executable '" + exeName + "' not found inside tar.gz archive.");
    }

    private static String baseName(String path) {
        int slash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        return slash >= 0 ? path.substring(slash + 1) : path;
    }

    private static void makeExecutable(Path path) {
        // POSIX chmod +x; a no-op on Windows where it is unnecessary.
        try {
            java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x");
            Files.setPosixFilePermissions(path, perms);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX filesystem (Windows): executability is not controlled by permissions.
            path.toFile().setExecutable(true, false);
        }
    }

    private Path cacheDir() {
        String override = System.getenv("BANBO_CACHE_DIR");
        Path base;
        if (override != null && !override.trim().isEmpty()) {
            base = Paths.get(override.trim());
        } else if (isWindows()) {
            String localAppData = System.getenv("LOCALAPPDATA");
            base = (localAppData != null && !localAppData.isEmpty())
                    ? Paths.get(localAppData, "banbo", "cache")
                    : Paths.get(userHome(), ".cache", "banbo");
        } else {
            // Respect XDG on Linux; fall back to ~/.cache (also used on macOS for simplicity).
            String xdg = System.getenv("XDG_CACHE_HOME");
            base = (xdg != null && !xdg.isEmpty())
                    ? Paths.get(xdg, "banbo")
                    : Paths.get(userHome(), ".cache", "banbo");
        }
        return base.resolve(version).toAbsolutePath();
    }

    private static String userHome() {
        return System.getProperty("user.home", ".");
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    // --- platform detection -------------------------------------------------

    /** Detected host operating system and architecture, mapped to banbo's naming. */
    static final class Platform {
        final String os;   // linux | darwin | windows
        final String arch; // amd64 | arm64

        private Platform(String os, String arch) {
            this.os = os;
            this.arch = arch;
        }

        static Platform detect() {
            String rawOs = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            String rawArch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);

            String os;
            if (rawOs.contains("win")) {
                os = "windows";
            } else if (rawOs.contains("mac") || rawOs.contains("darwin")) {
                os = "darwin";
            } else if (rawOs.contains("nux") || rawOs.contains("nix")) {
                os = "linux";
            } else {
                throw new BanboException("Unsupported operating system: " + rawOs);
            }

            String arch;
            if (rawArch.equals("amd64") || rawArch.equals("x86_64") || rawArch.equals("x64")) {
                arch = "amd64";
            } else if (rawArch.equals("aarch64") || rawArch.equals("arm64")) {
                arch = "arm64";
            } else {
                throw new BanboException("Unsupported architecture: " + rawArch);
            }

            return new Platform(os, arch);
        }

        String ext() {
            return os.equals("windows") ? "zip" : "tar.gz";
        }

        String executableName() {
            return os.equals("windows") ? "banbo.exe" : "banbo";
        }

        String archiveName() {
            return "banbo_" + os + "_" + arch + "." + ext();
        }
    }

    // --- stream draining ----------------------------------------------------

    private static final class StreamCollector implements Runnable {
        private final InputStream stream;
        private final java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        private volatile IOException error;

        StreamCollector(InputStream stream) {
            this.stream = stream;
        }

        @Override
        public void run() {
            byte[] chunk = new byte[8192];
            int n;
            try {
                while ((n = stream.read(chunk)) != -1) {
                    buffer.write(chunk, 0, n);
                }
            } catch (IOException e) {
                this.error = e;
            }
        }

        String content() {
            return new String(buffer.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }
}
