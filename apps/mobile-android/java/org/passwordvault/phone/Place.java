// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.os.Bundle;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * Who would get what autofill fills, or whose login it saves: the app, as the system names it,
 * what it is signed with, and, when the fields are in a web page, that page's own domain and
 * scheme. It is put together from the very fields that are filled ({@link Fields}), so a domain
 * never comes from another part of the screen than they do.
 *
 * What may be offered there is decided by the app (vault_mobile::autofill::Recipient): a website
 * only when a browser known by its certificate names it.
 */
final class Place {
    private static final String APP = "org.passwordvault.phone.APP";
    private static final String DOMAIN = "org.passwordvault.phone.DOMAIN";
    private static final String SCHEME = "org.passwordvault.phone.SCHEME";

    /** The app's package. */
    final String app;
    /** The web page's domain ("" when there is one that gives none), or null: not in a page. */
    final String domain;
    /** The web page's scheme, or null when it isn't given. */
    final String scheme;
    /**
     * SHA-256 of the app's signing certificate and of those Android proved it was rotated from,
     * 32 bytes each, one after the other; empty when it has several signers or can't be seen.
     */
    final byte[] signers;
    /** The app opens any https link: a browser. */
    final boolean browser;

    private Place(Context context, String app, String domain, String scheme) {
        this.app = app;
        this.domain = domain;
        this.scheme = scheme;
        PackageManager packages = context.getPackageManager();
        signers = signersOf(packages, app);
        browser = opensAnyLink(packages, app);
    }

    /** Where {@code fields} of {@code app} are. */
    static Place of(Context context, String app, Fields fields) {
        return new Place(context, app, fields.webDomain, fields.webScheme);
    }

    /** Puts the place away next to the request it belongs to. */
    void write(Bundle to) {
        to.putString(APP, app);
        to.putString(DOMAIN, domain);
        to.putString(SCHEME, scheme);
    }

    /**
     * The place {@link #write} put away, or null. What the app is signed with is looked up again
     * now: it is the app there is at this moment that gets the answer.
     */
    static Place read(Context context, Bundle from) {
        String app = from == null ? null : from.getString(APP);
        return app == null ? null
                : new Place(context, app, from.getString(DOMAIN), from.getString(SCHEME));
    }

    /** Whether this is the place {@code other} was: the same app, and the same page in it. */
    boolean same(Place other) {
        return other != null && app.equals(other.app) && Objects.equals(domain, other.domain)
                && Objects.equals(scheme, other.scheme);
    }

    /**
     * What the prompt says the login goes to: {@code recipient}, as the app named it, and the
     * page's own word when that isn't it (a web page inside an app that isn't a browser).
     */
    String shown(String recipient) {
        return domain == null || domain.isEmpty() || domain.equalsIgnoreCase(recipient)
                ? recipient : recipient + " · " + domain;
    }

    private static byte[] signersOf(PackageManager packages, String app) {
        try {
            PackageInfo info = packages.getPackageInfo(app, PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.signingInfo == null || info.signingInfo.hasMultipleSigners()) {
                return new byte[0];
            }
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream digests = new ByteArrayOutputStream();
            for (Signature certificate : info.signingInfo.getSigningCertificateHistory()) {
                digests.write(sha256.digest(certificate.toByteArray()));
            }
            return digests.toByteArray();
        } catch (Exception e) {
            // Not there, or Android doesn't show it to this app: nothing vouches for it.
            return new byte[0];
        }
    }

    /**
     * Asked with an address no app is made for, so only what opens every https link answers.
     * When it can't be told, it counts as a browser: an unknown one gets nothing.
     */
    private static boolean opensAnyLink(PackageManager packages, String app) {
        try {
            Intent link = new Intent(Intent.ACTION_VIEW, Uri.parse("https://vault.invalid/"))
                    .addCategory(Intent.CATEGORY_BROWSABLE)
                    .setPackage(app);
            return !packages.queryIntentActivities(link, PackageManager.MATCH_ALL).isEmpty();
        } catch (Exception e) {
            return true;
        }
    }
}
