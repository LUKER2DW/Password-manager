// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.service.autofill.Dataset;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillManager;
import android.view.autofill.AutofillValue;
import android.widget.Toast;
import java.util.Arrays;

/**
 * What runs when an autofill offer is chosen: a screen of its own, with nothing on it but the
 * system's prompts. Every fill is confirmed first, with a fingerprint or the phone's own lock.
 *
 * What it answers goes to the app that started it, so that has to be the app the offer was made
 * for; who it is ({@link Place}) is worked out again here, its certificate included, and the
 * login is only one that belongs there.
 *
 * - One login of the open vault ({@link #ITEM}): confirmed, then its username and password.
 * - The vault locked: with fingerprint unlock on, a fingerprint opens the vault file here just
 *   long enough to read the logins for this place (several: the person picks one); otherwise
 *   the app opens, to be unlocked first.
 */
public class AutofillActivity extends Activity {
    static {
        System.loadLibrary("vault_mobile_android");
    }

    static final String ITEM = "org.passwordvault.phone.ITEM";
    static final String USERNAME = "org.passwordvault.phone.USERNAME";
    static final String PASSWORD = "org.passwordvault.phone.PASSWORD";

    private AutofillId usernameField;
    private AutofillId passwordField;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        Shield.guard(getWindow());
        Intent intent = getIntent();
        Place place = Place.read(this, intent.getExtras());
        String recipient = place == null || !place.app.equals(getCallingPackage())
                ? null : Autofill.recipient(place);
        if (recipient == null) {
            done(null);
            return;
        }
        String item = intent.getStringExtra(ITEM);
        usernameField = intent.getParcelableExtra(USERNAME);
        passwordField = intent.getParcelableExtra(PASSWORD);
        String shown = place.shown(recipient);
        String title = Autofill.word(this, "autofill_title");
        String cancel = Autofill.word(this, "autofill_cancel");

        if (item != null) {
            Biometrics.confirm(this, title, shown, cancel, (ok, error) -> {
                if (ok == null) {
                    refuse(error);
                    return;
                }
                // username, password; null when the vault was locked meanwhile.
                String[] login = Autofill.openLogin(item, place);
                if (login == null) {
                    openApp();
                } else {
                    fill(login[0], login[1]);
                }
            });
            return;
        }
        String home = getFilesDir().getAbsolutePath();
        String vault = Autofill.lockedVault(home);
        byte[] sealed = vault == null ? null : Autofill.lockedSealed(home);
        if (sealed == null || !Biometrics.available(this)) {
            openApp();
            return;
        }
        Biometrics.open(this, vault, sealed, title, shown, cancel, (secret, error) -> {
            if (secret == null) {
                refuse(error);
                return;
            }
            // title, username, password for each login.
            String[] found = Autofill.openWithSecret(home, secret, place);
            Arrays.fill(secret, (byte) 0);
            if (found == null) {
                openApp();
            } else {
                choose(found);
            }
        });
    }

    /** Several logins for this place: the person picks one. */
    private void choose(String[] found) {
        int count = found.length / 3;
        if (count == 0) {
            Toast.makeText(this, Autofill.word(this, "autofill_nothing"), Toast.LENGTH_LONG).show();
            done(null);
            return;
        }
        if (count == 1) {
            fill(found[1], found[2]);
            return;
        }
        String[] names = new String[count];
        for (int i = 0; i < count; i++) {
            String user = found[i * 3 + 1];
            names[i] = user.isEmpty() ? found[i * 3] : user + " · " + found[i * 3];
        }
        new AlertDialog.Builder(this)
                .setTitle(Autofill.word(this, "autofill_title"))
                .setItems(names, (dialog, which) -> fill(found[which * 3 + 1], found[which * 3 + 2]))
                .setOnCancelListener(dialog -> done(null))
                .show();
    }

    private void fill(String username, String password) {
        // The biometric prompt or account picker may have outlived the original caller.
        Place current = Place.read(this, getIntent().getExtras());
        if (current == null || !current.app.equals(getCallingPackage())
                || Autofill.recipient(current) == null) {
            done(null);
            return;
        }
        Dataset.Builder dataset = new Dataset.Builder();
        boolean any = false;
        android.widget.RemoteViews row = Autofill.row(this, username.isEmpty() ? "•••" : username, null);
        if (usernameField != null && !username.isEmpty()) {
            dataset.setValue(usernameField, AutofillValue.forText(username), row);
            any = true;
        }
        if (passwordField != null && !password.isEmpty()) {
            dataset.setValue(passwordField, AutofillValue.forText(password), row);
            any = true;
        }
        done(any ? dataset.build() : null);
    }

    private void done(Dataset dataset) {
        if (dataset == null) {
            setResult(RESULT_CANCELED);
        } else {
            Intent data = new Intent();
            data.putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset);
            setResult(RESULT_OK, data);
        }
        finish();
    }

    /** The prompt was cancelled (nothing to say) or couldn't run (the reason, briefly). */
    private void refuse(String error) {
        if ("no_lock".equals(error)) {
            Toast.makeText(this, Autofill.word(this, "autofill_no_lock"), Toast.LENGTH_LONG).show();
        } else if (error != null && !error.isEmpty() && !"invalidated".equals(error)) {
            Toast.makeText(this, error, Toast.LENGTH_LONG).show();
        } else if ("invalidated".equals(error)) {
            Toast.makeText(this, Autofill.word(this, "autofill_open_app"), Toast.LENGTH_LONG).show();
        }
        done(null);
    }

    /** The vault has to be unlocked in the app first (or its master password is due). */
    private void openApp() {
        Toast.makeText(this, Autofill.word(this, "autofill_open_app"), Toast.LENGTH_LONG).show();
        startActivity(new Intent(this, VaultActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        done(null);
    }
}
