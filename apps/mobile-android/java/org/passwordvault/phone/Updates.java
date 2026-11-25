// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.Manifest;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;

/**
 * Installing an update of the app. The app has checked that the file is the one its server
 * announced (size and SHA-256), which says nothing of who made it: here it has to be this app,
 * newer, and signed with the same certificate, before Android's installer gets it (Android
 * checks the signature again).
 *
 * The installer's answers come to {@link InstallReceiver}, which no other app can reach, through
 * the one PendingIntent the install session was committed with. Only the session started last,
 * with the number made for it, is listened to.
 */
final class Updates {
    /** Why an update isn't installed (the words are the app's, Words.error). */
    static final String NOT_THIS_APP = "package";
    static final String OTHER_SIGNATURE = "signature";
    static final String NOT_NEWER = "older";
    static final String NO_INSTALLER = "installer";

    private static final String ANSWER = "org.passwordvault.phone.INSTALLED";
    private static final String NONCE = "org.passwordvault.phone.NONCE";
    private static final String FILE = "update";

    /** The session this app committed and waits to hear about, and the number made for it. */
    private static int session = -1;
    private static long nonce;

    private Updates() {}

    /** Hands the update to the system's installer; null, or why it isn't installed. */
    static String install(Context context, byte[] apk) throws Exception {
        String problem = check(context, apk);
        if (problem != null) {
            return problem;
        }
        PackageInstaller installer = context.getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(context.getPackageName());
        int id = installer.createSession(params);
        long number = new SecureRandom().nextLong();
        waitFor(id, number);
        try (PackageInstaller.Session open = installer.openSession(id)) {
            try (OutputStream out = open.openWrite("vault.apk", 0, apk.length)) {
                out.write(apk);
                open.fsync(out);
            }
            // To the receiver by name; the installer fills in its answer, so it stays mutable,
            // but what is put here stays as it is.
            Intent back = new Intent(context, InstallReceiver.class).setAction(ANSWER)
                    .putExtra(NONCE, number);
            int flags = PendingIntent.FLAG_UPDATE_CURRENT
                    | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
            PendingIntent pending = PendingIntent.getBroadcast(context, id, back, flags);
            open.commit(pending.getIntentSender());
        } catch (Exception e) {
            drop(context);
            throw e;
        }
        return null;
    }

    /** Null when the file may go to the installer, else why not. */
    private static String check(Context context, byte[] apk) throws IOException {
        File cache = context.getCacheDir();
        // What a stopped app left (not secret: the app's own package).
        File[] left = cache.listFiles((dir, name) -> name.startsWith(FILE) && name.endsWith(".apk"));
        if (left != null) {
            for (File file : left) {
                file.delete();
            }
        }
        // Android reads a package from a file; the installer gets these same bytes.
        File file = File.createTempFile(FILE, ".apk", cache);
        try {
            try (FileOutputStream out = new FileOutputStream(file)) {
                out.write(apk);
            }
            return problem(context.getPackageManager(), context.getPackageName(), file);
        } finally {
            file.delete();
        }
    }

    static String problem(PackageManager packages, String own, File file) {
        // Older versions of Android read a file's certificates only when asked the older way as
        // well; without them no update could be told from a forged one, so none would go in.
        int flags = PackageManager.GET_SIGNING_CERTIFICATES | PackageManager.GET_SIGNATURES;
        PackageInfo update = packages.getPackageArchiveInfo(file.getPath(), flags);
        if (update == null || !own.equals(update.packageName)) {
            return NOT_THIS_APP;
        }
        PackageInfo here;
        try {
            here = packages.getPackageInfo(own, flags);
        } catch (PackageManager.NameNotFoundException e) {
            return NOT_THIS_APP;
        }
        if (!sameSigners(here.signingInfo, update.signingInfo)) {
            return OTHER_SIGNATURE;
        }
        return update.getLongVersionCode() > here.getLongVersionCode() ? null : NOT_NEWER;
    }

    /** The very same certificates sign both (a change of certificate isn't taken from here). */
    private static boolean sameSigners(SigningInfo one, SigningInfo other) {
        Signature[] first = one == null ? null : one.getApkContentsSigners();
        Signature[] second = other == null ? null : other.getApkContentsSigners();
        return first != null && second != null && first.length > 0
                && new HashSet<>(Arrays.asList(first)).equals(new HashSet<>(Arrays.asList(second)));
    }

    private static synchronized void waitFor(int id, long number) {
        session = id;
        nonce = number;
    }

    /** Nothing more is waited for. */
    static synchronized void forget() {
        session = -1;
    }

    /** Gives the install up: its session goes, and its answers count for nothing. */
    static synchronized void drop(Context context) {
        int id = session;
        session = -1;
        try {
            context.getPackageManager().getPackageInstaller().abandonSession(id);
        } catch (Exception e) {
            // Gone already.
        }
    }

    /** Whether this is the answer to the session this app committed last. */
    static synchronized boolean expected(Intent answer) {
        return session != -1
                && ANSWER.equals(answer.getAction())
                && answer.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1) == session
                && answer.hasExtra(NONCE)
                && answer.getLongExtra(NONCE, 0) == nonce;
    }

    /**
     * The system's own "install this?" screen for the session, or null when the answer doesn't
     * lead to it. The intent in the answer isn't started: it only names the screen, which has to
     * be one of a system app that may install packages, and a new one is made for it with
     * nothing else in it but the session.
     */
    static synchronized Intent confirmation(Context context, Intent answer) {
        Intent named = answer.getParcelableExtra(Intent.EXTRA_INTENT);
        if (named == null || named.getAction() == null || session == -1) {
            return null;
        }
        PackageManager packages = context.getPackageManager();
        ComponentName screen = named.resolveActivity(packages);
        if (screen == null || context.getPackageName().equals(screen.getPackageName())) {
            return null;
        }
        String app = screen.getPackageName();
        try {
            boolean system = (packages.getApplicationInfo(app, 0).flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            boolean installs = packages.checkPermission(Manifest.permission.INSTALL_PACKAGES, app)
                    == PackageManager.PERMISSION_GRANTED;
            if (!system || !installs) {
                return null;
            }
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }
        return new Intent(named.getAction())
                .setPackage(app)
                .putExtra(PackageInstaller.EXTRA_SESSION_ID, session);
    }
}
