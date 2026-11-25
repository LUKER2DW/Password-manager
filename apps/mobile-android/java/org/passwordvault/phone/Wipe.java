// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;

/** Overwrites what was decrypted before it is let go. */
final class Wipe {
    private static final int BLOCK = 64 * 1024;

    private Wipe() {}

    /**
     * Zeros over everything behind {@code channel}, as long as it is now, and onto the storage.
     * Answers how many bytes that was.
     */
    static long zero(FileChannel channel) throws IOException {
        long length = channel.size();
        ByteBuffer zeros = ByteBuffer.allocate(BLOCK);
        long at = 0;
        while (at < length) {
            zeros.clear();
            zeros.limit((int) Math.min(BLOCK, length - at));
            at += channel.write(zeros, at);
        }
        channel.force(true);
        return length;
    }

    /**
     * Overwrites a file, then deletes it (which happens whatever the overwriting came to).
     * Opening it doesn't cut it short: its length is what there is to overwrite. A link is only
     * deleted, never followed. Answers how many bytes were overwritten.
     */
    static long file(File file) {
        long wiped = 0;
        if (file.isFile() && !Files.isSymbolicLink(file.toPath())) {
            try (RandomAccessFile open = new RandomAccessFile(file, "rw")) {
                wiped = zero(open.getChannel());
            } catch (IOException e) {
                // Deleted below anyway.
            }
        }
        file.delete();
        return wiped;
    }
}
