// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.NativeActivity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * The app's activity: Android's NativeActivity, which runs the app (a Rust library, see
 * crates/mobile-android/src/lib.rs), plus the one thing native code can't do on its own:
 * asking the system's file picker for a file to open or a place to save one, and hearing back.
 *
 * Files are read and written here, through the content resolver, off the main thread; what was
 * read (or read back after saving) goes to the app as bytes. Nothing here sees a password or a
 * key: a vault file is encrypted.
 */
public class VaultActivity extends NativeActivity {
    static {
        // Already loaded by NativeActivity; loading it here too lets the JVM find the native
        // methods below in it.
        System.loadLibrary("vault_mobile_android");
    }

    private static final int OPEN = 1;
    private static final int SAVE = 2;
    /** Largest file read (a vault, or a picture holding a recovery part). */
    private static final int MAX = 64 * 1024 * 1024;

    private byte[] pendingSave;

    /** The picker, for a file to open. The answer comes to {@link #opened}. */
    public void openDocument() {
        runOnUiThread(() -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            startActivityForResult(intent, OPEN);
        });
    }

    /** The picker, for where to save {@code data} as {@code name}. The answer comes to {@link #saved}. */
    public void createDocument(String name, byte[] data) {
        runOnUiThread(() -> {
            pendingSave = data;
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("application/octet-stream");
            intent.putExtra(Intent.EXTRA_TITLE, name);
            startActivityForResult(intent, SAVE);
        });
    }

    /** Back at the app's first screen: to the background, as Home does, instead of closing. */
    public void leave() {
        runOnUiThread(() -> moveTaskToBack(true));
    }

    /** Deletes a document saved here (a copy that failed its check). */
    public boolean deleteDocument(String uri) {
        try {
            return DocumentsContract.deleteDocument(getContentResolver(), Uri.parse(uri));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        final Uri uri = (result == RESULT_OK && data != null) ? data.getData() : null;
        if (request == OPEN) {
            if (uri == null) {
                opened(null, null, null);
                return;
            }
            new Thread(() -> {
                try (InputStream in = getContentResolver().openInputStream(uri)) {
                    opened(displayName(uri), readAll(in), null);
                } catch (Exception e) {
                    opened(null, null, String.valueOf(e.getMessage()));
                }
            }).start();
        } else if (request == SAVE) {
            final byte[] bytes = pendingSave;
            pendingSave = null;
            if (uri == null || bytes == null) {
                saved(null, null, null, null);
                return;
            }
            new Thread(() -> {
                try {
                    try (OutputStream out = getContentResolver().openOutputStream(uri, "wt")) {
                        out.write(bytes);
                    }
                    byte[] back;
                    try (InputStream in = getContentResolver().openInputStream(uri)) {
                        back = readAll(in);
                    }
                    saved(uri.toString(), displayName(uri), back, null);
                } catch (Exception e) {
                    saved(uri.toString(), null, null, String.valueOf(e.getMessage()));
                }
            }).start();
        }
    }

    private String displayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(
                uri, new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                return cursor.getString(0);
            }
        } catch (Exception e) {
            // The name is only shown; the file itself is what counts.
        }
        return uri.getLastPathSegment();
    }

    private static byte[] readAll(InputStream in) throws Exception {
        if (in == null) {
            throw new Exception("the file can't be opened");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[64 * 1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
            if (out.size() > MAX) {
                throw new Exception("the file is too large");
            }
        }
        return out.toByteArray();
    }

    /** A file was chosen and read ({@code data}), or not ({@code data} null: cancelled, or {@code error}). */
    private static native void opened(String name, byte[] data, String error);

    /** A copy was saved at {@code uri} and read back ({@code readBack}), or not. */
    private static native void saved(String uri, String name, byte[] readBack, String error);
}
