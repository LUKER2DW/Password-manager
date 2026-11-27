// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.KeyguardManager;
import android.app.NativeActivity;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.database.Cursor;
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
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.Locale;

/**
 * The app's activity: Android's NativeActivity, which runs the app (a Rust library, see
 * apps/mobile-android/src/lib.rs), plus what native code can't do on its own: the system's file
 * picker and "save as", Google's code scanner for a QR code, fingerprint unlock (Biometrics) and
 * the check before each use of a secret, keeping the screens out of screenshots, Android's
 * autofill settings, installing an update, and telling the app when it leaves the screen and
 * comes back.
 *
 * Files are read and written here, through the content resolver, off the main thread; what was
 * read (or read back after saving) goes to the app as bytes. Nothing here sees a password or the
 * vault key: a vault file is encrypted, and fingerprint unlock only seals a device secret. The one
 * decrypted thing that passes through is a PDF attached to an item, while its preview is drawn
 * (PdfPreview).
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
    private static final int SEALED = 1;
    private static final int OPENED = 2;
    /** {@link #bioDone}: the person passed the check before one use of a secret. */
    private static final int CONFIRMED = 3;

    private byte[] pendingSave;
    /** A system prompt (the phone's unlock) is on screen, or waits for the window's focus. */
    private boolean prompting;
    private Runnable waitingPrompt;
    /** One of the app's own system screens is up (a picker, a settings page, the installer). */
    private boolean away;
    /** The activity there is, for the installer's answer (InstallReceiver). */
    private static WeakReference<VaultActivity> current = new WeakReference<>(null);

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

    private PdfPreview pdf;

    /** Whether the person kept the app out of screenshots (Settings), see {@link #setSecure}. */
    private boolean secure;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        current = new WeakReference<>(this);
        // The recent apps view never shows what was on screen, screenshots allowed or not.
        if (Build.VERSION.SDK_INT >= 33) {
            setRecentsScreenshotEnabled(false);
        }
        // A preview's file left behind by an earlier run (an older version of the app kept it
        // there while drawing).
        PdfPreview.cleanUp(getCacheDir());
    }

    /**
     * Opens a PDF attached to an item for its preview, drawn here by Android's own renderer
     * ({@link PdfPreview}, which wipes {@code data}). Answers how many pages it has, or -1.
     * {@link #pdfClose} ends it, whatever happened in between.
     */
    public int pdfOpen(byte[] data) {
        pdfClose();
        try {
            pdf = new PdfPreview(getCacheDir(), data);
            return pdf.pages();
        } catch (Exception | OutOfMemoryError e) {
            pdfClose();
            return -1;
        }
    }

    /** A page's size in points, the width in the upper 32 bits, or -1. */
    public long pdfSize(int index) {
        return pdf == null ? -1 : pdf.size(index);
    }

    /** A page drawn on white at this many pixels, as RGBA bytes; null when it can't be. */
    public byte[] pdfPage(int index, int width, int height) {
        return pdf == null ? null : pdf.page(index, width, height);
    }

    /** Closes the PDF and wipes the decrypted bytes the renderer read. */
    public void pdfClose() {
        PdfPreview open = pdf;
        pdf = null;
        if (open != null) {
            open.close();
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

    // ---- every use asks ----

    /** The phone has a screen lock (PIN, pattern or password), so Android can check the person. */
    public boolean screenLockSet() {
        KeyguardManager keyguard = getSystemService(KeyguardManager.class);
        return keyguard != null && keyguard.isDeviceSecure();
    }

    /**
     * Asks for a strong biometric or the screen lock before one use of a secret (Settings, "Ask
     * for the fingerprint or screen lock every time"): the system's own prompt, as before every
     * autofill. The answer comes to {@link #bioDone}: an empty array once passed, else "" when
     * cancelled, "no_lock" when the phone has no screen lock, or what went wrong.
     */
    public void confirmPerson(String title, String subtitle, String cancel) {
        whenShown(() -> Biometrics.confirm(this, title, subtitle, cancel, (data, error) -> {
            prompting = false;
            bioDone(CONFIRMED, data, error);
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
     * Hands an update (an APK) to the system's installer ({@link Updates}): only this app, newer
     * and signed with the same certificate. Android asks the person. The answer comes to
     * {@link #installStatus}: "" once Android asks, else why not.
     */
    public void installUpdate(byte[] apk) {
        new Thread(() -> {
            String problem;
            try {
                problem = Updates.install(this, apk);
            } catch (Exception e) {
                problem = String.valueOf(e.getMessage());
            }
            if (problem != null) {
                installStatus(problem);
            }
        }).start();
    }

    /** The installer's answer to the session this app started, from {@link InstallReceiver}. */
    static void installAnswered(Intent answer) {
        VaultActivity activity = current.get();
        if (activity != null) {
            activity.answered(answer);
        }
    }

    private void answered(Intent answer) {
        int status = answer.getIntExtra(PackageInstaller.EXTRA_STATUS,
                PackageInstaller.STATUS_FAILURE);
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            Intent confirm = Updates.confirmation(this, answer);
            try {
                if (confirm != null) {
                    away = true;
                    startActivity(confirm);
                    installStatus("");
                    return;
                }
            } catch (Exception e) {
                away = false;
            }
            Updates.drop(this);
            installStatus(Updates.NO_INSTALLER);
            return;
        }
        Updates.forget();
        if (status != PackageInstaller.STATUS_SUCCESS) {
            installStatus(String.valueOf(answer.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)));
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

    /** A fingerprint prompt's answer: what was sealed or opened (or confirmed), or why not. */
    private static native void bioDone(int purpose, byte[] data, String error);

    /** The app left the screen (not for one of its own system screens). */
    private static native void appLeft();

    /** The app is on screen again; {@code fromOwnScreen} after one of its own system screens. */
    private static native void appBack(boolean fromOwnScreen);

    /** The installer's answer: "" when Android asks the person, else why it can't. */
    private static native void installStatus(String error);
}
