// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.CancellationSignal;
import android.os.OutcomeReceiver;
import androidx.credentials.exceptions.ClearCredentialException;
import androidx.credentials.exceptions.CreateCredentialException;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.provider.AuthenticationAction;
import androidx.credentials.provider.BeginCreateCredentialRequest;
import androidx.credentials.provider.BeginCreateCredentialResponse;
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest;
import androidx.credentials.provider.BeginGetCredentialOption;
import androidx.credentials.provider.BeginGetCredentialRequest;
import androidx.credentials.provider.BeginGetCredentialResponse;
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption;
import androidx.credentials.provider.CreateEntry;
import androidx.credentials.provider.CredentialProviderService;
import androidx.credentials.provider.ProviderClearCredentialStateRequest;
import androidx.credentials.provider.PublicKeyCredentialEntry;

/**
 * Passkeys from the vault for the browsers and apps on the phone, through Android's Credential
 * Manager (Android 14 on; the person turns Vault on in the phone's settings, under passwords
 * and accounts). Android asks first, before the person chooses anything; nothing secret
 * leaves here, only who each passkey is for. What is chosen runs in {@link PasskeyActivity},
 * after a fingerprint or the phone's lock.
 *
 * - Sign-in, the vault open in the app: one entry per passkey that answers there.
 * - Sign-in, the vault locked: "Unlock Vault", which opens the vault file with the fingerprint
 *   and then lists the passkeys.
 * - A new passkey: one entry, "Vault"; it is made there, in the open vault or, while it is
 *   locked, in the vault file opened with the fingerprint.
 *
 * The app never answers itself.
 */
public class VaultCredentialService extends CredentialProviderService {
    static {
        System.loadLibrary("vault_mobile_android");
    }

    @Override
    public void onBeginCreateCredentialRequest(BeginCreateCredentialRequest request,
            CancellationSignal cancel,
            OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException> callback) {
        BeginCreateCredentialResponse.Builder response = new BeginCreateCredentialResponse.Builder();
        if (!(request instanceof BeginCreatePublicKeyCredentialRequest)
                || request.getCallingAppInfo() == null
                || getPackageName().equals(request.getCallingAppInfo().getPackageName())) {
            callback.onResult(response.build());
            return;
        }
        Intent intent = new Intent(this, PasskeyActivity.class).setAction(PasskeyActivity.CREATE);
        CreateEntry entry = new CreateEntry.Builder(Autofill.word(this, "passkey_account"),
                pending(this, intent))
                .setDescription(Autofill.word(this, "passkey_create_detail"))
                .build();
        callback.onResult(response.addCreateEntry(entry).build());
    }

    @Override
    public void onBeginGetCredentialRequest(BeginGetCredentialRequest request,
            CancellationSignal cancel,
            OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException> callback) {
        new Thread(() -> {
            BeginGetCredentialResponse.Builder response = new BeginGetCredentialResponse.Builder();
            Passkeys.Asker asker = Passkeys.asker(request.getCallingAppInfo());
            if (asker == null || getPackageName().equals(asker.app)
                    || Passkeys.caller(asker) == null) {
                callback.onResult(response.build());
                return;
            }
            boolean locked = false;
            for (BeginGetCredentialOption option : request.getBeginGetCredentialOptions()) {
                if (!(option instanceof BeginGetPublicKeyCredentialOption)) {
                    continue;
                }
                BeginGetPublicKeyCredentialOption passkey = (BeginGetPublicKeyCredentialOption) option;
                String[] offers = Passkeys.offers(asker, passkey.getRequestJson());
                if (offers == null) {
                    locked = true;
                } else {
                    addEntries(this, response, passkey, offers, false);
                }
            }
            if (locked) {
                Intent intent = new Intent(this, PasskeyActivity.class)
                        .setAction(PasskeyActivity.UNLOCK);
                response.addAuthenticationAction(new AuthenticationAction(
                        Autofill.word(this, "passkey_unlock"), pending(this, intent)));
            }
            callback.onResult(response.build());
        }).start();
    }

    @Override
    public void onClearCredentialStateRequest(ProviderClearCredentialStateRequest request,
            CancellationSignal cancel, OutcomeReceiver<Void, ClearCredentialException> callback) {
        // No sign-in state is kept for a caller.
        callback.onResult(null);
    }

    /**
     * One entry per passkey in {@code offers} (item, credential, title, account name, display
     * name). {@code held}: read with the fingerprint a moment ago ({@link Passkeys#hold}).
     */
    static void addEntries(Context context, BeginGetCredentialResponse.Builder response,
            BeginGetPublicKeyCredentialOption option, String[] offers, boolean held) {
        for (int i = 0; i + 4 < offers.length; i += 5) {
            Intent intent = new Intent(context, PasskeyActivity.class)
                    .setAction(PasskeyActivity.GET)
                    .putExtra(PasskeyActivity.ITEM, offers[i])
                    .putExtra(PasskeyActivity.CREDENTIAL, offers[i + 1])
                    .putExtra(PasskeyActivity.HELD, held);
            String title = offers[i + 2];
            String user = offers[i + 3].isEmpty() ? title : offers[i + 3];
            String shown = offers[i + 4].isEmpty() ? title : offers[i + 4];
            response.addCredentialEntry(
                    new PublicKeyCredentialEntry.Builder(context, user, pending(context, intent), option)
                            .setDisplayName(shown)
                            .build());
        }
    }

    /** A pending intent of its own for {@code intent}; Android adds the request to it. */
    static PendingIntent pending(Context context, Intent intent) {
        return PendingIntent.getActivity(context, Passkeys.nextRequest(), intent,
                PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }
}
