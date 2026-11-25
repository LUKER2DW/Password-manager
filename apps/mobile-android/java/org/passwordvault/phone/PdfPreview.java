// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.pdf.PdfRenderer;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;

/**
 * A PDF attached to an item, while its preview is drawn by Android's own renderer, which reads
 * it from a file descriptor. From Android 11 that is memory with no name (memfd): the decrypted
 * PDF touches no storage. Before that it is a file in the app's private cache, its name deleted
 * as soon as it is open. Either way it is overwritten when the preview closes, whatever failed
 * on the way.
 *
 * How large and how many the pages are is decided in Rust (vault_mobile::system::PageBudget) and
 * held to here again, before a bitmap is made.
 */
final class PdfPreview implements Closeable {
    // The same numbers as PageBudget (a test there reads them here).
    static final int MAX_PAGES = 40;
    static final int MAX_WIDTH = 1080;
    static final int MAX_HEIGHT = 4096;
    static final long MAX_BYTES = 96L * 1024 * 1024;

    private static final String PREFIX = "preview";
    private static final String SUFFIX = ".pdf";

    private final Copy copy;
    private final PdfRenderer renderer;
    private int drawnPages;
    private long drawnBytes;

    /** Opens {@code data}, which is wiped. What it needed is closed again when it can't. */
    PdfPreview(File cache, byte[] data) throws IOException {
        copy = copyOf(cache, data);
        PdfRenderer opened = null;
        try {
            opened = new PdfRenderer(copy.reader);
        } finally {
            // Also for the unchecked ones: a PDF with a password, or no memory left.
            if (opened == null) {
                copy.close();
            }
        }
        renderer = opened;
    }

    /** Overwrites and deletes what a stopped app left in {@code cache}. */
    static void cleanUp(File cache) {
        File[] left = cache.listFiles((dir, name) -> name.startsWith(PREFIX) && name.endsWith(SUFFIX));
        if (left != null) {
            for (File file : left) {
                Wipe.file(file);
            }
        }
    }

    int pages() {
        return renderer.getPageCount();
    }

    /** A page's size in points, the width in the upper 32 bits; -1 when it can't be read. */
    long size(int index) {
        if (index < 0 || index >= Math.min(MAX_PAGES, pages())) {
            return -1;
        }
        try (PdfRenderer.Page page = renderer.openPage(index)) {
            return ((long) page.getWidth() << 32) | (page.getHeight() & 0xFFFFFFFFL);
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Page {@code index} drawn on white at exactly this many pixels, as RGBA bytes; null when it
     * can't be drawn, or isn't within the budget.
     */
    byte[] page(int index, int width, int height) {
        if (index < 0 || index >= pages() || width < 1 || height < 1
                || width > MAX_WIDTH || height > MAX_HEIGHT) {
            return null;
        }
        long bytes = 4L * width * height;
        if (drawnPages >= MAX_PAGES || bytes > MAX_BYTES - drawnBytes) {
            return null;
        }
        Bitmap bitmap = null;
        try (PdfRenderer.Page page = renderer.openPage(index)) {
            bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
            if (bitmap.getByteCount() != bytes) {
                return null;
            }
            bitmap.eraseColor(Color.WHITE);
            page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);
            ByteBuffer pixels = ByteBuffer.allocate((int) bytes);
            bitmap.copyPixelsToBuffer(pixels);
            drawnPages++;
            drawnBytes += bytes;
            return pixels.array();
        } catch (Exception | OutOfMemoryError e) {
            return null;
        } finally {
            if (bitmap != null) {
                bitmap.recycle();
            }
        }
    }

    /** Closes the renderer and its descriptor, and overwrites the decrypted bytes. */
    @Override
    public void close() {
        try {
            renderer.close();
        } catch (Exception e) {
            // Closed already; what matters is the copy.
        } finally {
            copy.close();
        }
    }

    // ---- the decrypted bytes ----

    private static Copy copyOf(File cache, byte[] data) throws IOException {
        Copy copy = null;
        boolean written = false;
        try {
            copy = inMemory();
            if (copy == null) {
                copy = inFile(cache);
            }
            ByteBuffer bytes = ByteBuffer.wrap(data);
            while (bytes.hasRemaining()) {
                copy.channel.write(bytes);
            }
            written = true;
            return copy;
        } finally {
            Arrays.fill(data, (byte) 0);
            if (copy != null && !written) {
                copy.close();
            }
        }
    }

    /** Memory only this process can reach; null where Android has none (before 11, old kernels). */
    private static Copy inMemory() {
        if (Build.VERSION.SDK_INT < 30) {
            return null;
        }
        FileDescriptor memory = null;
        try {
            memory = Os.memfd_create(PREFIX, OsConstants.MFD_CLOEXEC);
            FileDescriptor owned = memory;
            Copy copy = new Copy(ParcelFileDescriptor.dup(memory),
                    new FileOutputStream(memory).getChannel(), () -> closeQuietly(owned));
            memory = null;
            return copy;
        } catch (Exception e) {
            return null;
        } finally {
            closeQuietly(memory);
        }
    }

    private static Copy inFile(File cache) throws IOException {
        File path = File.createTempFile(PREFIX, SUFFIX, cache);
        RandomAccessFile file = null;
        try {
            file = new RandomAccessFile(path, "rw");
            Copy copy = new Copy(ParcelFileDescriptor.dup(file.getFD()), file.getChannel(), file);
            file = null;
            return copy;
        } finally {
            if (file != null) {
                file.close();
            }
            // The bytes stay reachable only through the descriptors: stopped in the middle, the
            // app leaves no file behind.
            path.delete();
        }
    }

    private static void closeQuietly(FileDescriptor descriptor) {
        if (descriptor != null) {
            try {
                Os.close(descriptor);
            } catch (Exception e) {
                // Closed already.
            }
        }
    }

    /** The decrypted bytes: what the renderer reads them by, and what wipes them. */
    private static final class Copy {
        /** The renderer's own descriptor. */
        final ParcelFileDescriptor reader;
        final FileChannel channel;
        private final Closeable below;

        Copy(ParcelFileDescriptor reader, FileChannel channel, Closeable below) {
            this.reader = reader;
            this.channel = channel;
            this.below = below;
        }

        /**
         * Each step whatever came of the one before, an unchecked exception included (a
         * descriptor the renderer took over and closed, say): one left open would keep the
         * memory, or the file without a name, for as long as the app runs.
         */
        void close() {
            try {
                Wipe.zero(channel);
            } catch (Exception e) {
                // Closed below anyway: the memory, or the file without a name, goes with it.
            }
            for (Closeable each : new Closeable[] {reader, channel, below}) {
                try {
                    each.close();
                } catch (Exception e) {
                    // Closed already.
                }
            }
        }
    }
}
