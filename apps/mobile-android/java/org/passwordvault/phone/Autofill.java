// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.content.Context;
import android.view.View;
import android.widget.RemoteViews;

/**
 * What autofill asks of the app (a Rust library, src/autofill.rs), and the rows of its offers.
 * Only logins saved for exactly the asking website or app come back, and none behind the item
 * lock.
 */
final class Autofill {
    private Autofill() {}

    /** id, title, username of each login for this place in the vault open in the app; null when locked. */
    static native String[] openLogins(String domain, String app);

    /** username, password of one of those logins; null when the vault is locked or it doesn't fit. */
    static native String[] openLogin(String item, String domain, String app);

    /** The vault the app opened last, when fingerprint unlock is on for it and fresh. */
    static native String lockedVault(String home);

    /** That vault's device secret, sealed by the phone's secure hardware. */
    static native byte[] lockedSealed(String home);

    /**
     * title, username, password of each login for this place, opening the vault with the device
     * secret; null when it can't.
     */
    static native String[] openWithSecret(String home, byte[] secret, String domain, String app);

    /** A strong password from the app's generator. */
    static native String suggest();

    /** Saves a login from another app: into the open vault, or its drop box while locked. */
    static native boolean save(String home, String domain, String app, String username,
            String password);

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

    /** A word from the app's own resources (res/values*), in the phone's language. */
    static String word(Context context, String name) {
        return context.getString(id(context, "string", name));
    }

    private static int id(Context context, String type, String name) {
        return context.getResources().getIdentifier(name, type, context.getPackageName());
    }
}
