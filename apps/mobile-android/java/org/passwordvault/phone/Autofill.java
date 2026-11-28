// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.content.Context;
import android.view.View;
import android.widget.RemoteViews;

/**
 * What autofill asks of the app (a Rust library, src/autofill.rs), and the rows of its offers.
 * Every question says who asks ({@link Place}); only logins saved for exactly that website or app
 * come back, and none behind the item lock. The native methods work out from the place's parts,
 * each time, who it is and whether it gets anything.
 */
final class Autofill {
    /** {@link #save}: it couldn't be saved. */
    static final int NOT_SAVED = 0;
    /** {@link #save}: it is in the vault, or will be at the next unlock. */
    static final int SAVED = 1;
    /** {@link #save}: as a login of its own, since the one it had is behind the item lock. */
    static final int SAVED_BESIDE = 2;

    private Autofill() {}

    /** The website or app the place stands for; null when nothing is offered or saved there. */
    static String recipient(Place at) {
        return recipient(at.app, at.signers, at.browser, at.domain, at.scheme);
    }

    /** id, title, username of each login for this place in the vault open in the app; null when locked. */
    static String[] openLogins(Place at) {
        return openLogins(at.app, at.signers, at.browser, at.domain, at.scheme);
    }

    /** username, password of one of those logins; null when the vault is locked or it doesn't fit. */
    static String[] openLogin(String item, Place at) {
        return openLogin(item, at.app, at.signers, at.browser, at.domain, at.scheme);
    }

    /**
     * title, username, password of each login for this place, opening the vault with the device
     * secret; null when it can't.
     */
    static String[] openWithSecret(String home, byte[] secret, Place at) {
        return openWithSecret(home, secret, at.app, at.signers, at.browser, at.domain, at.scheme);
    }

    /** Saves a login from another app: into the open vault, or its drop box while locked. */
    static int save(String home, Place from, String username, String password) {
        return save(home, from.app, from.signers, from.browser, from.domain, from.scheme,
                username, password);
    }

    private static native String recipient(String app, byte[] signers, boolean browser,
            String domain, String scheme);

    private static native String[] openLogins(String app, byte[] signers, boolean browser,
            String domain, String scheme);

    private static native String[] openLogin(String item, String app, byte[] signers,
            boolean browser, String domain, String scheme);

    private static native String[] openWithSecret(String home, byte[] secret, String app,
            byte[] signers, boolean browser, String domain, String scheme);

    private static native int save(String home, String app, byte[] signers, boolean browser,
            String domain, String scheme, String username, String password);

    /** The vault the app opened last, when fingerprint unlock is on for it and fresh. */
    static native String lockedVault(String home);

    /** That vault's device secret, sealed by the phone's secure hardware. */
    static native byte[] lockedSealed(String home);

    /** A strong password from the app's generator. */
    static native String suggest();

    /**
     * Whether a frame at {@code frame} inside a page at {@code top} are one site's (the same
     * registrable domain); false when either is empty.
     */
    static native boolean sameSite(String top, String frame);

    /** One line of the offer: a name, and under it, smaller, another. */
    static RemoteViews row(Context context, String first, String second) {
        RemoteViews row = new RemoteViews(context.getPackageName(), id(context, "layout", "autofill_row"));
        row.setTextViewText(id(context, "id", "first"), first);
        if (second == null) {
            row.setViewVisibility(id(context, "id", "second"), View.GONE);
        } else {
            row.setTextViewText(id(context, "id", "second"), second);
        }
        return row;
    }

    /** The signed app identity shown when Android asks whether to save or rebind a login. */
    static RemoteViews identity(Context context, String app, String signer) {
        RemoteViews identity = new RemoteViews(
                context.getPackageName(), id(context, "layout", "autofill_identity"));
        identity.setTextViewText(id(context, "id", "first"), app);
        identity.setTextViewText(id(context, "id", "second"),
                word(context, "autofill_signer") + "\n" + signer);
        return identity;
    }

    /** A word from the app's own resources (res/values*), in the phone's language. */
    static String word(Context context, String name) {
        return context.getString(id(context, "string", name));
    }

    private static int id(Context context, String type, String name) {
        return context.getResources().getIdentifier(name, type, context.getPackageName());
    }
}
