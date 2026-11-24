// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.NativeActivity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.pdf.PdfRenderer;
import android.os.ParcelFileDescriptor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.view.WindowManager;
import android.view.autofill.AutofillManager;
import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Locale;

/**
 * The app's activity: Android's NativeActivity, which runs the app (a Rust library, see
 * apps/mobile-android/src/lib.rs), plus what native code can't do on its own: the system's file
 * picker and "save as", Google's code scanner for a QR code, fingerprint unlock (Biometrics),
 * keeping the screens out of screenshots, Android's autofill settings, installing an update, and
 * telling the app when it leaves the screen and comes back.
 *
 * Files are read and written here, through the content resolver, off the main thread; what was
 * read (or read back after saving) goes to the app as bytes. Nothing here sees a password or the
 * vault key: a vault file is encrypted, and fingerprint unlock only seals a device secret. The one
 * decrypted thing that passes through is a PDF attached to an item, while its preview is drawn
 * (pdfOpen).
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
    /** The installer's answer comes back to this activity with this action. */
    private static final String INSTALLED = "org.passwordvault.phone.INSTALLED";
    private static final int SEALED = 1;
    private static final int OPENED = 2;

    private byte[] pendingSave;
    /** A system prompt (the phone's unlock) is on screen, or waits for the window's focus. */
    private boolean prompting;
    private Runnable waitingPrompt;
    /** One of the app's own system screens is up (a picker, a settings page, the installer). */
    private boolean away;
    /** The install session this app committed and waits to hear about, or -1. */
    private volatile int installing = -1;

    // ---- files ----

    /** The picker, for a file to open. The answer comes to {@link #opened}. */
    public void openDocument() {
        runOnUiThread(() -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            away = true;
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
            away = true;
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

    // ---- the camera ----

    /**
     * Google's code scanner (Play services), for the QR code a computer shows under Add a
     * device ({@code purpose} says where its line goes). Its camera screen is Play services'
     * own, so this app needs no camera permission and sees only the code's text. The answer
     * comes to {@link #scanned}: the text, nothing when cancelled, or "unavailable" when the
     * phone has no Play services (the line can be pasted instead).
     */
    public void scanCode(int purpose) {
        runOnUiThread(() -> {
            away = true;
            GmsBarcodeScannerOptions options = new GmsBarcodeScannerOptions.Builder()
                    .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                    .enableAutoZoom()
                    .build();
            GmsBarcodeScanning.getClient(this, options).startScan()
                    .addOnSuccessListener(code -> scanned(purpose, code.getRawValue(), null))
                    .addOnCanceledListener(() -> scanned(purpose, null, null))
                    .addOnFailureListener(e -> scanned(purpose, null, "unavailable"));
        });
    }

    // ---- links and PDFs ----

    /** A web address in the phone's browser (the app passes http and https only). */
    public void openLink(String url) {
        Uri uri = Uri.parse(url);
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))) {
            return;
        }
        runOnUiThread(() -> {
            try {
                away = true;
                startActivity(new Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE));
            } catch (Exception e) {
                away = false;
            }
        });
    }

    private PdfRenderer pdf;
    private ParcelFileDescriptor pdfFile;
    private File pdfPath;

    /** Whether the person kept the app out of screenshots (Settings), see {@link #setSecure}. */
    private boolean secure;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        // The recent apps view never shows what was on screen, screenshots allowed or not.
        if (Build.VERSION.SDK_INT >= 33) {
            setRecentsScreenshotEnabled(false);
        }
        // A preview's file left behind when the app was stopped while drawing it.
        File[] left = getCacheDir().listFiles((dir, name) -> name.startsWith("preview") && name.endsWith(".pdf"));
        if (left != null) {
            for (File file : left) {
                wipe(file);
            }
        }
    }

    /** Overwrites a file with zeros, then deletes it. */
    private static void wipe(File file) {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(new byte[(int) Math.min(file.length(), 64L * 1024 * 1024)]);
        } catch (Exception e) {
            // Deleted below anyway.
        }
        file.delete();
    }

    /**
     * Opens a PDF attached to an item for its preview, drawn here by Android's own renderer:
     * the decrypted file is written to this app's private cache (the renderer reads a file),
     * read, and deleted by {@link #pdfClose}. Answers how many pages it has, or -1.
     */
    public int pdfOpen(byte[] data) {
        pdfClose();
        try {
            pdfPath = File.createTempFile("preview", ".pdf", getCacheDir());
            try (FileOutputStream out = new FileOutputStream(pdfPath)) {
                out.write(data);
            }
            pdfFile = ParcelFileDescriptor.open(pdfPath, ParcelFileDescriptor.MODE_READ_ONLY);
            pdf = new PdfRenderer(pdfFile);
            return pdf.getPageCount();
        } catch (Exception e) {
            pdfClose();
            return -1;
        }
    }

    /** Page {@code index} drawn {@code width} pixels wide on white, as RGBA bytes. */
    public byte[] pdfPage(int index, int width) {
        if (pdf == null || index < 0 || index >= pdf.getPageCount()) {
            return null;
        }
        try (PdfRenderer.Page page = pdf.openPage(index)) {
            int height = Math.max(1, (int) ((long) width * page.getHeight() / Math.max(1, page.getWidth())));
            Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
            bitmap.eraseColor(Color.WHITE);
            page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);
            ByteBuffer pixels = ByteBuffer.allocate(bitmap.getByteCount());
            bitmap.copyPixelsToBuffer(pixels);
            bitmap.recycle();
            return pixels.array();
        } catch (Exception e) {
            return null;
        }
    }

    /** Closes the PDF and deletes its file (overwritten first). */
    public void pdfClose() {
        try {
            if (pdf != null) {
                pdf.close();
            }
            if (pdfFile != null) {
                pdfFile.close();
            }
        } catch (Exception e) {
            // Closed already.
        }
        pdf = null;
        pdfFile = null;
        if (pdfPath != null) {
            wipe(pdfPath);
            pdfPath = null;
        }
    }

    // ---- fingerprint unlock ----

    public boolean biometricsAvailable() {
        return Biometrics.available(this);
    }

    /** Seals {@code secret} after the phone's unlock; the answer comes to {@link #bioDone}. */
    public void sealWithBiometrics(String vaultId, byte[] secret, String title, String subtitle,
            String cancel) {
        whenShown(() -> Biometrics.seal(this, vaultId, secret, title, subtitle, cancel,
                (data, error) -> {
                    prompting = false;
                    bioDone(SEALED, data, error);
                }));
    }

    /** Opens a sealed secret after the phone's unlock; the answer comes to {@link #bioDone}. */
    public void openWithBiometrics(String vaultId, byte[] sealed, String title, String subtitle,
            String cancel) {
        whenShown(() -> Biometrics.open(this, vaultId, sealed, title, subtitle, cancel,
                (data, error) -> {
                    prompting = false;
                    bioDone(OPENED, data, error);
                    if (data != null) {
                        Arrays.fill(data, (byte) 0);
                    }
                }));
    }

    /**
     * Shows a system prompt once this screen is in front with the focus (one asked for while the
     * app is still starting would be cancelled by Android as the window comes up, and stay on
     * screen without answering), and only one at a time: while one is up, it answers.
     */
    private void whenShown(Runnable prompt) {
        runOnUiThread(() -> {
            if (prompting) {
                return;
            }
            if (hasWindowFocus()) {
                prompting = true;
                prompt.run();
            } else {
                waitingPrompt = prompt;
            }
        });
    }

    @Override
    public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (focused && waitingPrompt != null && !prompting) {
            Runnable prompt = waitingPrompt;
            waitingPrompt = null;
            prompting = true;
            prompt.run();
        }
    }

    public void forgetBiometrics(String vaultId) {
        Biometrics.forget(vaultId);
    }

    // ---- the system ----

    /** Keeps the app out of screenshots, recordings and the recent apps view, or not. */
    public void setSecure(boolean on) {
        runOnUiThread(() -> {
            secure = on;
            if (on) {
                getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
            } else {
                getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            }
        });
    }

    /** How far this phone's clock is from UTC now, in minutes (summer time included). */
    public int utcOffsetMinutes() {
        return java.util.TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60000;
    }

    /** -1 no autofill on this phone, 0 another service (or none), 1 this app. */
    public int autofillState() {
        AutofillManager manager = getSystemService(AutofillManager.class);
        if (manager == null || !manager.isAutofillSupported()) {
            return -1;
        }
        return manager.hasEnabledAutofillServices() ? 1 : 0;
    }

    /** Android's screen for choosing the autofill service, with this app offered. */
    public void openAutofillSettings() {
        runOnUiThread(() -> {
            Intent intent = new Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE,
                    Uri.parse("package:" + getPackageName()));
            away = true;
            try {
                startActivity(intent);
            } catch (Exception e) {
                away = false;
            }
        });
    }

    /** The phone's language, as a tag ("pt-BR"). */
    public String language() {
        return Locale.getDefault().toLanguageTag();
    }

    /** The installed app's version name. */
    public String appVersion() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Hands an update (an APK) to the system's installer. Android asks the person and installs
     * it only if it is signed with the same key as this app. The answer comes to
     * {@link #installStatus}: "" once Android asks, else why not.
     */
    public void installUpdate(byte[] apk) {
        new Thread(() -> {
            try {
                PackageInstaller installer = getPackageManager().getPackageInstaller();
                PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                        PackageInstaller.SessionParams.MODE_FULL_INSTALL);
                params.setAppPackageName(getPackageName());
                int id = installer.createSession(params);
                try (PackageInstaller.Session session = installer.openSession(id)) {
                    try (OutputStream out = session.openWrite("vault.apk", 0, apk.length)) {
                        out.write(apk);
                        session.fsync(out);
                    }
                    Intent back = new Intent(this, VaultActivity.class).setAction(INSTALLED);
                    int flags = PendingIntent.FLAG_UPDATE_CURRENT
                            | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
                    PendingIntent pending = PendingIntent.getActivity(this, id, back, flags);
                    installing = id;
                    session.commit(pending.getIntentSender());
                }
            } catch (Exception e) {
                installing = -1;
                installStatus(String.valueOf(e.getMessage()));
            }
        }).start();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // The activity is exported (it is the launcher), so any app can send it this action:
        // only the session this app committed counts, and the screen it hands over is started
        // only when it belongs to another app (the system's installer), without URI grants.
        // Otherwise another app could have this one start its own, not exported, activities.
        if (!INSTALLED.equals(intent.getAction())
                || installing == -1
                || intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -2) != installing) {
            return;
        }
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS,
                PackageInstaller.STATUS_FAILURE);
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            Intent confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT);
            ComponentName target = confirm == null ? null
                    : confirm.resolveActivity(getPackageManager());
            if (target != null && !getPackageName().equals(target.getPackageName())) {
                confirm.removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                        | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                        | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
                away = true;
                startActivity(confirm);
            }
            installStatus("");
            return;
        }
        installing = -1;
        if (status != PackageInstaller.STATUS_SUCCESS) {
            installStatus(String.valueOf(intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)));
        }
    }

    // ---- leaving and coming back ----

    // Before Android 13 there is no way to leave the screen out of the recent apps view but
    // the secure flag: set while the app is in the background, so the picture Android takes
    // as it leaves is blank, and taken off again on return when screenshots are allowed.
    @Override
    protected void onPause() {
        super.onPause();
        if (Build.VERSION.SDK_INT < 33 && !secure) {
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (Build.VERSION.SDK_INT < 33 && !secure) {
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (!away) {
            appLeft();
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        boolean own = away;
        away = false;
        appBack(own);
    }

    // ---- answers from the pickers ----

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

    /** A QR code's text, or none: cancelled, or {@code error} ("unavailable": no Play services). */
    private static native void scanned(int purpose, String text, String error);

    /** A copy was saved at {@code uri} and read back ({@code readBack}), or not. */
    private static native void saved(String uri, String name, byte[] readBack, String error);

    /** A fingerprint prompt's answer: what was sealed or opened, or why not. */
    private static native void bioDone(int purpose, byte[] data, String error);

    /** The app left the screen (not for one of its own system screens). */
    private static native void appLeft();

    /** The app is on screen again; {@code fromOwnScreen} after one of its own system screens. */
    private static native void appBack(boolean fromOwnScreen);

    /** The installer's answer: "" when Android asks the person, else why it can't. */
    private static native void installStatus(String error);
}
