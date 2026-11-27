// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import androidx.credentials.provider.CallingAppInfo;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;

/**
 * What the passkey provider asks of the app (a Rust library, src/passkeys.rs; the decisions are
 * vault_mobile::passkeys). Every question says who asks ({@link Asker}): the calling app as
 * Android names it, what it is signed with, and, for a browser this app lists as privileged,
 * the web page's origin, which Android vouches for. Who that stands for, and which passkeys
 * answer there, is worked out again on the Rust side each time.
 */
final class Passkeys {
    private Passkeys() {}

    /** Request codes of the pending intents, so that each one stays its own. */
    private static int requests;

    static synchronized int nextRequest() {
        return ++requests;
    }

    /** Who asks for a passkey, as Android says it. */
    static final class Asker {
        final String app;
        /** SHA-256 of the current signing certificate, then the ones it was rotated from. */
        final byte[] signers;
        /** The page's origin, given only to a browser this app lists; null for an app. */
        final String origin;

        private Asker(String app, byte[] signers, String origin) {
            this.app = app;
            this.signers = signers;
            this.origin = origin;
        }
    }

    /** Who asks, from the calling app Android describes; null when it can't be told. */
    static Asker asker(CallingAppInfo info) {
        if (info == null) {
            return null;
        }
        String origin = null;
        try {
            if (info.isOriginPopulated()) {
                // Null unless the caller is one of these browsers, signed as listed.
                origin = info.getOrigin(privilegedBrowsers());
            }
        } catch (RuntimeException e) {
            origin = null;
        }
        return new Asker(info.getPackageName(), signersOf(info.getSigningInfo()), origin);
    }

    private static byte[] signersOf(SigningInfo signing) {
        try {
            if (signing == null || signing.hasMultipleSigners()) {
                return new byte[0];
            }
            Signature[] history = signing.getSigningCertificateHistory();
            if (history == null || history.length == 0) {
                return new byte[0];
            }
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream digests = new ByteArrayOutputStream();
            // Android gives the oldest first; the current one goes first here.
            for (int i = history.length - 1; i >= 0; i--) {
                digests.write(sha256.digest(history[i].toByteArray()));
            }
            return digests.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    /** Who asks, for the prompt: the page's host or the app's package; null when nobody. */
    static String caller(Asker asker) {
        return caller(asker.app, asker.signers, asker.origin);
    }

    /**
     * item, credential, title, account name, display name of each passkey of the open vault
     * that may answer {@code request}; null while the vault is locked or the app not running.
     */
    static String[] offers(Asker asker, String request) {
        return offers(asker.app, asker.signers, asker.origin, request);
    }

    /** The open vault's answer with one passkey, or null. */
    static String sign(Asker asker, String item, String credential, String request, byte[] hash) {
        return sign(asker.app, asker.signers, asker.origin, item, credential, request, hash);
    }

    /**
     * A passkey made in the open vault: {answer, title}, or {"", refusal}; null while the vault
     * is locked.
     */
    static String[] create(Asker asker, String request, byte[] hash) {
        return create(asker.app, asker.signers, asker.origin, request, hash);
    }

    /**
     * With the vault locked: opens it with the device secret, keeps the passkeys that answer
     * {@code request} ready for a minute, and returns them as {@link #offers} does.
     */
    static String[] hold(String home, byte[] secret, Asker asker, String request) {
        return hold(home, secret, asker.app, asker.signers, asker.origin, request);
    }

    /** The answer of one of the passkeys {@link #hold} keeps, or null once they are gone. */
    static String signHeld(Asker asker, String item, String credential, String request, byte[] hash) {
        return signHeld(asker.app, asker.signers, asker.origin, item, credential, request, hash);
    }

    /**
     * With the vault locked: opens the vault file with the device secret, makes the passkey and
     * saves the file. {answer, title}, or {"", refusal}.
     */
    static String[] createWithSecret(String home, byte[] secret, Asker asker, String request,
            byte[] hash) {
        return createWithSecret(home, secret, asker.app, asker.signers, asker.origin, request, hash);
    }

    /** The browsers Android may tell a page's origin to, as {@code getOrigin} reads them. */
    static native String privilegedBrowsers();

    /** Whether the running app has its vault open. */
    static native boolean vaultOpen();

    private static native String caller(String app, byte[] signers, String origin);

    private static native String[] offers(String app, byte[] signers, String origin,
            String request);

    private static native String sign(String app, byte[] signers, String origin, String item,
            String credential, String request, byte[] hash);

    private static native String[] create(String app, byte[] signers, String origin,
            String request, byte[] hash);

    private static native String[] hold(String home, byte[] secret, String app, byte[] signers,
            String origin, String request);

    private static native String signHeld(String app, byte[] signers, String origin, String item,
            String credential, String request, byte[] hash);

    private static native String[] createWithSecret(String home, byte[] secret, String app,
            byte[] signers, String origin, String request, byte[] hash);
}
