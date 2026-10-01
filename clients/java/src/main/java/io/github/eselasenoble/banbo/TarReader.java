package io.github.eselasenoble.banbo;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Minimal reader for the POSIX ustar / GNU tar format — just enough to locate a
 * single file entry by name and stream its contents.
 *
 * <p>Implemented directly so the client depends only on Jackson (no
 * commons-compress). Handles the standard 512-byte header layout, octal size
 * fields, and GNU/ustar name prefixes.</p>
 */
final class TarReader {

    private static final int BLOCK = 512;

    private TarReader() {
    }

    /** Callback invoked for the matching entry; the stream is positioned at the entry body. */
    interface EntryConsumer {
        void accept(InputStream entryBody, long size) throws IOException;
    }

    /**
     * Scans a tar stream and invokes {@code consumer} for the first entry whose
     * base file name equals {@code targetBaseName}.
     *
     * @return {@code true} if a matching entry was found and consumed
     */
    static boolean forFirstMatch(InputStream in, String targetBaseName, EntryConsumer consumer)
            throws IOException {
        byte[] header = new byte[BLOCK];

        while (true) {
            if (!readFully(in, header, 0, BLOCK)) {
                return false; // truncated / end of stream
            }
            if (isAllZero(header)) {
                return false; // end-of-archive marker
            }

            String name = parseName(header);
            long size = parseOctal(header, 124, 12);
            char typeFlag = (char) (header[156] & 0xff);

            // Regular file type flags: '0' or NUL.
            boolean isRegular = typeFlag == '0' || typeFlag == '\0';

            if (isRegular && baseName(name).equals(targetBaseName)) {
                LimitedInputStream body = new LimitedInputStream(in, size);
                consumer.accept(body, size);
                body.drain();
                skipPadding(in, size);
                return true;
            }

            // Skip this entry's body plus padding to the next 512-byte boundary.
            skipExactly(in, size);
            skipPadding(in, size);
        }
    }

    private static String parseName(byte[] header) {
        String name = parseString(header, 0, 100);
        String prefix = parseString(header, 345, 155); // ustar prefix field
        if (!prefix.isEmpty()) {
            return prefix + "/" + name;
        }
        return name;
    }

    private static String parseString(byte[] buf, int offset, int len) {
        int end = offset;
        int limit = offset + len;
        while (end < limit && buf[end] != 0) {
            end++;
        }
        return new String(buf, offset, end - offset, StandardCharsets.UTF_8);
    }

    private static long parseOctal(byte[] buf, int offset, int len) {
        long value = 0;
        int i = offset;
        int limit = offset + len;
        // Skip leading spaces / NULs.
        while (i < limit && (buf[i] == ' ' || buf[i] == 0)) {
            i++;
        }
        while (i < limit) {
            byte b = buf[i];
            if (b < '0' || b > '7') {
                break;
            }
            value = (value << 3) + (b - '0');
            i++;
        }
        return value;
    }

    private static boolean isAllZero(byte[] buf) {
        for (byte b : buf) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static String baseName(String path) {
        int slash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        return slash >= 0 ? path.substring(slash + 1) : path;
    }

    private static void skipPadding(InputStream in, long size) throws IOException {
        long remainder = size % BLOCK;
        if (remainder != 0) {
            skipExactly(in, BLOCK - remainder);
        }
    }

    private static void skipExactly(InputStream in, long n) throws IOException {
        long remaining = n;
        byte[] scratch = new byte[8192];
        while (remaining > 0) {
            int toRead = (int) Math.min(scratch.length, remaining);
            int read = in.read(scratch, 0, toRead);
            if (read == -1) {
                throw new IOException("Unexpected end of tar stream while skipping.");
            }
            remaining -= read;
        }
    }

    private static boolean readFully(InputStream in, byte[] buf, int off, int len)
            throws IOException {
        int total = 0;
        while (total < len) {
            int read = in.read(buf, off + total, len - total);
            if (read == -1) {
                return total == len;
            }
            total += read;
        }
        return true;
    }

    /** Caps reads to a fixed number of bytes and can drain any unread remainder. */
    private static final class LimitedInputStream extends InputStream {
        private final InputStream delegate;
        private long remaining;

        LimitedInputStream(InputStream delegate, long limit) {
            this.delegate = delegate;
            this.remaining = limit;
        }

        @Override
        public int read() throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int b = delegate.read();
            if (b != -1) {
                remaining--;
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int toRead = (int) Math.min(len, remaining);
            int read = delegate.read(b, off, toRead);
            if (read > 0) {
                remaining -= read;
            }
            return read;
        }

        void drain() throws IOException {
            byte[] scratch = new byte[8192];
            while (remaining > 0) {
                int toRead = (int) Math.min(scratch.length, remaining);
                int read = delegate.read(scratch, 0, toRead);
                if (read == -1) {
                    break;
                }
                remaining -= read;
            }
        }
    }
}
