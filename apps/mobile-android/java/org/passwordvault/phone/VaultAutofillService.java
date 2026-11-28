// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Intent;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.service.autofill.AutofillService;
import android.service.autofill.CustomDescription;
import android.service.autofill.Dataset;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveInfo;
import android.service.autofill.SaveRequest;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillValue;
import android.widget.Toast;
import java.util.List;

/**
 * Android's autofill, answered from the vault. A sign-in form in another app or in a browser
 * asks; this finds its fields ({@link Fields}) and who is behind them ({@link Place}): the app,
 * what it is signed with, and the domain of the web page they are in. A website's logins are
 * offered only in a browser known by its certificate, on an https page; other browsers and
 * pages get nothing, other apps only what was saved for the app itself.
 *
 * - With the vault open in the app, each login saved for exactly that place is offered by its
 *   username and title; nothing secret leaves until one is chosen and the person confirms with
 *   a fingerprint or the phone's lock ({@link AutofillActivity}).
 * - With the vault locked, the offer is "Unlock Vault to fill": a fingerprint opens the vault
 *   just long enough to read the logins for that place.
 * - On a password field, "Use a strong password" fills one made by the app's generator.
 * - After a sign-in or sign-up, Android asks "Save to Vault?"; the login goes into the open
 *   vault, or, while it is locked, into its drop box for the next unlock. It is saved for the
 *   place the offer was made for, or not at all; a login behind the item lock isn't changed
 *   (the new password becomes a login of its own).
 *
 * The app never fills itself.
 */
public class VaultAutofillService extends AutofillService {
    static {
        System.loadLibrary("vault_mobile_android");
    }

    private static int requests;

    @Override
    public void onFillRequest(FillRequest request, CancellationSignal cancel, FillCallback callback) {
        List<FillContext> contexts = request.getFillContexts();
        AssistStructure structure = contexts.get(contexts.size() - 1).getStructure();
        String app = structure.getActivityComponent().getPackageName();
        if (getPackageName().equals(app)) {
            callback.onSuccess(null);
            return;
        }
        Fields fields = Fields.find(structure);
        // A frame of another site than the page around it: nothing is offered (Fields).
        if ((fields.password == null && fields.username == null) || fields.framedByAnotherSite()) {
            callback.onSuccess(null);
            return;
        }
        new Thread(() -> {
            try {
                Place place = Place.of(this, app, fields);
                String recipient = Autofill.recipient(place);
                callback.onSuccess(recipient == null ? null : respond(fields, place, recipient));
            } catch (Exception e) {
                callback.onFailure(String.valueOf(e.getMessage()));
            }
        }).start();
    }

    private FillResponse respond(Fields fields, Place place, String recipient) {
        FillResponse.Builder response = new FillResponse.Builder();
        boolean any = false;
        // id, title, username for each login (no passwords until one is chosen and confirmed).
        String[] logins = Autofill.openLogins(place);
        if (logins == null) {
            response.addDataset(locked(fields, place, null,
                    Autofill.word(this, "autofill_unlock"), null));
            any = true;
        } else {
            for (int i = 0; i + 2 < logins.length; i += 3) {
                String user = logins[i + 2];
                response.addDataset(locked(fields, place, logins[i],
                        user.isEmpty() ? logins[i + 1] : user, user.isEmpty() ? null : logins[i + 1]));
                any = true;
            }
        }
        if (fields.password != null) {
            String strong = Autofill.suggest();
            if (strong != null) {
                Dataset.Builder suggestion = new Dataset.Builder();
                suggestion.setValue(fields.password, AutofillValue.forText(strong),
                        Autofill.row(this, Autofill.word(this, "autofill_suggest"),
                                Autofill.word(this, "autofill_suggest_detail")));
                response.addDataset(suggestion.build());
                any = true;
            }
            int types = SaveInfo.SAVE_DATA_TYPE_PASSWORD
                    | (fields.username != null ? SaveInfo.SAVE_DATA_TYPE_USERNAME : 0);
            SaveInfo.Builder save = new SaveInfo.Builder(types, new AutofillId[] {fields.password});
            if (fields.username != null) {
                save.setOptionalIds(new AutofillId[] {fields.username});
            }
            // A legacy package-only facet is rebound only through this explicit save. Show the
            // complete signer that will be recorded so package text is never the whole identity.
            if (place.app.equals(recipient)) {
                save.setCustomDescription(new CustomDescription.Builder(
                        Autofill.identity(this, recipient, place.currentSigner())).build());
            }
            response.setSaveInfo(save.build());
            // Comes back with the save: it is for this place and this password field.
            Bundle asked = new Bundle();
            place.write(asked);
            asked.putParcelable(AutofillActivity.PASSWORD, fields.password);
            response.setClientState(asked);
            any = true;
        }
        return any ? response.build() : null;
    }

    /**
     * An offer whose values come only after {@link AutofillActivity} confirms: one login
     * ({@code item}), or, with the vault locked ({@code item} null), whichever the person picks.
     */
    private Dataset locked(Fields fields, Place place, String item, String first, String second) {
        Bundle asked = new Bundle();
        place.write(asked);
        Intent intent = new Intent(this, AutofillActivity.class)
                .putExtras(asked)
                .putExtra(AutofillActivity.ITEM, item)
                .putExtra(AutofillActivity.USERNAME, fields.username)
                .putExtra(AutofillActivity.PASSWORD, fields.password);
        // Android adds the form to this intent when the offer is chosen: it must stay mutable.
        // What is put here stays as it is: an intent filled in keeps its own extras.
        int flags = PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_MUTABLE;
        PendingIntent pending = PendingIntent.getActivity(this, ++requests, intent, flags);
        Dataset.Builder dataset = new Dataset.Builder();
        android.widget.RemoteViews row = Autofill.row(this, first, second);
        if (fields.username != null) {
            dataset.setValue(fields.username, null, row);
        }
        if (fields.password != null) {
            dataset.setValue(fields.password, null, row);
        }
        dataset.setAuthentication(pending.getIntentSender());
        return dataset.build();
    }

    @Override
    public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        List<FillContext> contexts = request.getFillContexts();
        AssistStructure structure = contexts.get(contexts.size() - 1).getStructure();
        String app = structure.getActivityComponent().getPackageName();
        if (getPackageName().equals(app)) {
            callback.onSuccess();
            return;
        }
        // The form the offer was made for, found again by its password field.
        Bundle state = request.getClientState();
        AutofillId password = state == null ? null : state.getParcelable(AutofillActivity.PASSWORD);
        Fields fields = password == null ? null : Fields.holding(structure, password);
        if (fields != null && (fields.passwordValue == null || fields.passwordValue.isEmpty()
                || fields.framedByAnotherSite())) {
            callback.onSuccess();
            return;
        }
        String home = getFilesDir().getAbsolutePath();
        new Thread(() -> {
            int saved = Autofill.NOT_SAVED;
            Place place = fields == null ? null : Place.of(this, app, fields);
            // Another app, or another page, than the one it was offered in: not saved.
            if (place != null && place.same(Place.read(this, state))) {
                String user = fields.usernameValue == null ? "" : fields.usernameValue;
                saved = Autofill.save(home, place, user, fields.passwordValue);
            }
            if (saved == Autofill.NOT_SAVED) {
                callback.onFailure(Autofill.word(this, "autofill_not_saved"));
                // Android only logs that message: the person is told here.
                tell("autofill_not_saved");
                return;
            }
            callback.onSuccess();
            if (saved == Autofill.SAVED_BESIDE) {
                tell("autofill_saved_beside");
            }
        }).start();
    }

    private void tell(String word) {
        new Handler(Looper.getMainLooper()).post(() ->
                Toast.makeText(this, Autofill.word(this, word), Toast.LENGTH_LONG).show());
    }
}
