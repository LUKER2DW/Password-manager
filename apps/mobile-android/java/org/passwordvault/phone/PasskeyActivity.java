// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;
import androidx.credentials.CreatePublicKeyCredentialRequest;
import androidx.credentials.CreatePublicKeyCredentialResponse;
import androidx.credentials.CredentialOption;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.GetPublicKeyCredentialOption;
import androidx.credentials.PublicKeyCredential;
import androidx.credentials.exceptions.CreateCredentialCancellationException;
import androidx.credentials.exceptions.CreateCredentialUnknownException;
import androidx.credentials.exceptions.GetCredentialCancellationException;
import androidx.credentials.exceptions.GetCredentialUnknownException;
import androidx.credentials.exceptions.domerrors.InvalidStateError;
import androidx.credentials.exceptions.domerrors.NotSupportedError;
import androidx.credentials.exceptions.domerrors.SecurityError;
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException;
import androidx.credentials.provider.BeginGetCredentialOption;
import androidx.credentials.provider.BeginGetCredentialRequest;
import androidx.credentials.provider.BeginGetCredentialResponse;
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption;
import androidx.credentials.provider.PendingIntentHandler;
import androidx.credentials.provider.ProviderCreateCredentialRequest;
import androidx.credentials.provider.ProviderGetCredentialRequest;
import java.util.Arrays;

/**
 * What runs when a passkey entry of {@link VaultCredentialService} is chosen: a screen of its
 * own with nothing on it but the system's prompts. Who asks is read again from the request
 * Android hands over here, never from the entry; nothing is signed or made before the person
 * confirms with a fingerprint or the phone's lock.
 *
 * - {@link #GET}: signs in with one passkey: from the open vault, or one of those read with
 *   the fingerprint a moment ago ({@link #HELD}).
 * - {@link #UNLOCK}: the vault locked; the fingerprint opens the vault file and the passkeys
 *   that answer the request are listed (and kept ready for a minute).
 * - {@link #CREATE}: makes a passkey and keeps it: in the open vault, or in the vault file
 *   opened with the fingerprint.
 */
public class PasskeyActivity extends Activity {
    static {
        System.loadLibrary("vault_mobile_android");
    }

    static final String GET = "org.passwordvault.phone.passkey.GET";
    static final String UNLOCK = "org.passwordvault.phone.passkey.UNLOCK";
    static final String CREATE = "org.passwordvault.phone.passkey.CREATE";
    static final String ITEM = "org.passwordvault.phone.passkey.ITEM";
    static final String CREDENTIAL = "org.passwordvault.phone.passkey.CREDENTIAL";
    static final String HELD = "org.passwordvault.phone.passkey.HELD";

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        Shield.guard(getWindow());
        String action = getIntent().getAction();
        if (GET.equals(action)) {
            get();
        } else if (UNLOCK.equals(action)) {
            unlock();
        } else if (CREATE.equals(action)) {
            create();
        } else {
            finish();
        }
    }

    // ---- sign-in ----

    private void get() {
        ProviderGetCredentialRequest request =
                PendingIntentHandler.retrieveProviderGetCredentialRequest(getIntent());
        GetPublicKeyCredentialOption option = request == null ? null : passkeyOption(request);
        Passkeys.Asker asker = request == null ? null : Passkeys.asker(request.getCallingAppInfo());
        String name = asker == null ? null : Passkeys.caller(asker);
        String item = getIntent().getStringExtra(ITEM);
        String credential = getIntent().getStringExtra(CREDENTIAL);
        if (option == null || name == null || item == null || credential == null) {
            failGet();
            return;
        }
        String json = option.getRequestJson();
        byte[] hash = option.getClientDataHash();
        if (getIntent().getBooleanExtra(HELD, false)) {
            // Read with the fingerprint a moment ago, for this very request: it was the check.
            String answer = Passkeys.signHeld(asker, item, credential, json, hash);
            if (answer != null) {
                answerGet(answer);
            } else {
                tell("passkey_open_app");
                cancelGet();
            }
            return;
        }
        Biometrics.confirm(this, Autofill.word(this, "passkey_title_get"), name,
                Autofill.word(this, "autofill_cancel"), (ok, error) -> {
                    if (ok == null) {
                        refuse(error);
                        cancelGet();
                        return;
                    }
                    String answer = Passkeys.sign(asker, item, credential, json, hash);
                    if (answer == null) {
                        // Locked meanwhile, or the passkey is gone.
                        tell("passkey_open_app");
                        cancelGet();
                    } else {
                        answerGet(answer);
                    }
                });
    }

    private static GetPublicKeyCredentialOption passkeyOption(ProviderGetCredentialRequest request) {
        for (CredentialOption option : request.getCredentialOptions()) {
            if (option instanceof GetPublicKeyCredentialOption) {
                return (GetPublicKeyCredentialOption) option;
            }
        }
        return null;
    }

    private void answerGet(String answer) {
        Intent result = new Intent();
        PendingIntentHandler.setGetCredentialResponse(result,
                new GetCredentialResponse(new PublicKeyCredential(answer)));
        setResult(RESULT_OK, result);
        finish();
    }

    private void failGet() {
        Intent result = new Intent();
        PendingIntentHandler.setGetCredentialException(result,
                new GetCredentialUnknownException("No passkey answers this request"));
        setResult(RESULT_OK, result);
        finish();
    }

    private void cancelGet() {
        Intent result = new Intent();
        PendingIntentHandler.setGetCredentialException(result,
                new GetCredentialCancellationException("Not signed in"));
        setResult(RESULT_OK, result);
        finish();
    }

    // ---- the vault locked: the fingerprint opens it to list the passkeys ----

    private void unlock() {
        BeginGetCredentialRequest request =
                PendingIntentHandler.retrieveBeginGetCredentialRequest(getIntent());
        Passkeys.Asker asker = request == null ? null : Passkeys.asker(request.getCallingAppInfo());
        String name = asker == null ? null : Passkeys.caller(asker);
        if (name == null) {
            listed(new BeginGetCredentialResponse.Builder().build());
            return;
        }
        String home = getFilesDir().getAbsolutePath();
        String vault = Autofill.lockedVault(home);
        byte[] sealed = vault == null ? null : Autofill.lockedSealed(home);
        if (sealed == null || !Biometrics.available(this)) {
            openApp();
            listed(new BeginGetCredentialResponse.Builder().build());
            return;
        }
        Biometrics.open(this, vault, sealed, Autofill.word(this, "passkey_title_get"), name,
                Autofill.word(this, "autofill_cancel"), (secret, error) -> {
                    BeginGetCredentialResponse.Builder response =
                            new BeginGetCredentialResponse.Builder();
                    if (secret == null) {
                        refuse(error);
                        listed(response.build());
                        return;
                    }
                    for (BeginGetCredentialOption option : request.getBeginGetCredentialOptions()) {
                        if (!(option instanceof BeginGetPublicKeyCredentialOption)) {
                            continue;
                        }
                        BeginGetPublicKeyCredentialOption passkey =
                                (BeginGetPublicKeyCredentialOption) option;
                        String[] offers = Passkeys.hold(home, secret, asker, passkey.getRequestJson());
                        if (offers != null) {
                            VaultCredentialService.addEntries(this, response, passkey, offers, true);
                        }
                    }
                    Arrays.fill(secret, (byte) 0);
                    listed(response.build());
                });
    }

    private void listed(BeginGetCredentialResponse response) {
        Intent result = new Intent();
        PendingIntentHandler.setBeginGetCredentialResponse(result, response);
        setResult(RESULT_OK, result);
        finish();
    }

    // ---- a new passkey ----

    private void create() {
        ProviderCreateCredentialRequest request =
                PendingIntentHandler.retrieveProviderCreateCredentialRequest(getIntent());
        if (request == null
                || !(request.getCallingRequest() instanceof CreatePublicKeyCredentialRequest)) {
            failCreate("");
            return;
        }
        CreatePublicKeyCredentialRequest asked =
                (CreatePublicKeyCredentialRequest) request.getCallingRequest();
        Passkeys.Asker asker = Passkeys.asker(request.getCallingAppInfo());
        String name = asker == null ? null : Passkeys.caller(asker);
        if (name == null) {
            failCreate("wrong_site");
            return;
        }
        String json = asked.getRequestJson();
        byte[] hash = asked.getClientDataHash();
        String title = Autofill.word(this, "passkey_title_create");
        String cancel = Autofill.word(this, "autofill_cancel");
        if (Passkeys.vaultOpen()) {
            Biometrics.confirm(this, title, name, cancel, (ok, error) -> {
                if (ok == null) {
                    refuse(error);
                    cancelCreate();
                    return;
                }
                String[] made = Passkeys.create(asker, json, hash);
                if (made == null) {
                    tell("passkey_open_app");
                    cancelCreate();
                } else {
                    made(made);
                }
            });
            return;
        }
        String home = getFilesDir().getAbsolutePath();
        String vault = Autofill.lockedVault(home);
        byte[] sealed = vault == null ? null : Autofill.lockedSealed(home);
        if (sealed == null || !Biometrics.available(this)) {
            openApp();
            cancelCreate();
            return;
        }
        Biometrics.open(this, vault, sealed, title, name, cancel, (secret, error) -> {
            if (secret == null) {
                refuse(error);
                cancelCreate();
                return;
            }
            String[] made = Passkeys.createWithSecret(home, secret, asker, json, hash);
            Arrays.fill(secret, (byte) 0);
            made(made);
        });
    }

    /** {answer, title} made; {"", refusal} not. */
    private void made(String[] made) {
        if (made == null || made.length < 2 || made[0].isEmpty()) {
            failCreate(made == null || made.length < 2 ? "" : made[1]);
            return;
        }
        Intent result = new Intent();
        PendingIntentHandler.setCreateCredentialResponse(result,
                new CreatePublicKeyCredentialResponse(made[0]));
        setResult(RESULT_OK, result);
        finish();
    }

    /** The site is told why, as a browser would (a DOM error), and the person too. */
    private void failCreate(String refusal) {
        Intent result = new Intent();
        switch (refusal) {
            case "exists":
                tell("passkey_exists");
                PendingIntentHandler.setCreateCredentialException(result,
                        new CreatePublicKeyCredentialDomException(new InvalidStateError(),
                                "A passkey for this account is in the vault already"));
                break;
            case "unsupported":
                PendingIntentHandler.setCreateCredentialException(result,
                        new CreatePublicKeyCredentialDomException(new NotSupportedError(),
                                "The site accepts no kind of passkey Vault makes"));
                break;
            case "wrong_site":
                PendingIntentHandler.setCreateCredentialException(result,
                        new CreatePublicKeyCredentialDomException(new SecurityError(),
                                "Not a site this caller may make passkeys for"));
                break;
            default:
                tell("passkey_not_saved");
                PendingIntentHandler.setCreateCredentialException(result,
                        new CreateCredentialUnknownException("The passkey couldn't be saved"));
        }
        setResult(RESULT_OK, result);
        finish();
    }

    private void cancelCreate() {
        Intent result = new Intent();
        PendingIntentHandler.setCreateCredentialException(result,
                new CreateCredentialCancellationException("No passkey made"));
        setResult(RESULT_OK, result);
        finish();
    }

    // ---- both ----

    /** The prompt was cancelled (nothing to say) or couldn't run (the reason, briefly). */
    private void refuse(String error) {
        if ("no_lock".equals(error)) {
            tell("autofill_no_lock");
        } else if ("invalidated".equals(error)) {
            tell("passkey_open_app");
        } else if (error != null && !error.isEmpty()) {
            Toast.makeText(this, error, Toast.LENGTH_LONG).show();
        }
    }

    private void tell(String word) {
        Toast.makeText(this, Autofill.word(this, word), Toast.LENGTH_LONG).show();
    }

    /** The vault has to be unlocked in the app first (or its master password is due). */
    private void openApp() {
        tell("passkey_open_app");
        startActivity(new Intent(this, VaultActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
    }
}
