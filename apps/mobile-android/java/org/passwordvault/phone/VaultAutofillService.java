// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Intent;
import android.os.Build;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
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
import java.util.List;

/**
 * Android's autofill, answered from the vault. A sign-in form in another app or in a browser
 * asks; this finds its fields and where they are (the website's domain, or the app's package).
 *
 * - With the vault open in the app, each login saved for exactly that place is offered by its
 *   username and title; nothing secret leaves until one is chosen and the person confirms with
 *   a fingerprint or the phone's lock ({@link AutofillActivity}).
 * - With the vault locked, the offer is "Unlock Vault to fill": a fingerprint opens the vault
 *   just long enough to read the logins for that place.
 * - On a password field, "Use a strong password" fills one made by the app's generator.
 * - After a sign-in or sign-up, Android asks "Save to Vault?"; the login goes into the open
 *   vault, or, while it is locked, into its drop box for the next unlock.
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
        if (fields.password == null && fields.username == null) {
            callback.onSuccess(null);
            return;
        }
        new Thread(() -> {
            try {
                callback.onSuccess(respond(fields, app));
            } catch (Exception e) {
                callback.onFailure(String.valueOf(e.getMessage()));
            }
        }).start();
    }

    private FillResponse respond(Fields fields, String app) {
        FillResponse.Builder response = new FillResponse.Builder();
        boolean any = false;
        // id, title, username for each login (no passwords until one is chosen and confirmed).
        String[] logins = Autofill.openLogins(fields.webDomain, app);
        if (logins == null) {
            response.addDataset(locked(fields, app, null,
                    Autofill.word(this, "autofill_unlock"), null));
            any = true;
        } else {
            for (int i = 0; i + 2 < logins.length; i += 3) {
                String user = logins[i + 2];
                response.addDataset(locked(fields, app, logins[i],
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
            response.setSaveInfo(save.build());
            any = true;
        }
        return any ? response.build() : null;
    }

    /**
     * An offer whose values come only after {@link AutofillActivity} confirms: one login
     * ({@code item}), or, with the vault locked ({@code item} null), whichever the person picks.
     */
    private Dataset locked(Fields fields, String app, String item, String first, String second) {
        Intent intent = new Intent(this, AutofillActivity.class)
                .putExtra(AutofillActivity.DOMAIN, fields.webDomain)
                .putExtra(AutofillActivity.APP, app)
                .putExtra(AutofillActivity.ITEM, item)
                .putExtra(AutofillActivity.USERNAME, fields.username)
                .putExtra(AutofillActivity.PASSWORD, fields.password);
        // Android adds the form to this intent when the offer is chosen: it must stay mutable.
        int flags = PendingIntent.FLAG_CANCEL_CURRENT
                | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
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
        Fields fields = Fields.find(structure);
        if (getPackageName().equals(app) || fields.passwordValue == null
                || fields.passwordValue.isEmpty()) {
            callback.onSuccess();
            return;
        }
        String home = getFilesDir().getAbsolutePath();
        String user = fields.usernameValue == null ? "" : fields.usernameValue;
        new Thread(() -> {
            if (Autofill.save(home, fields.webDomain, app, user, fields.passwordValue)) {
                callback.onSuccess();
            } else {
                callback.onFailure(Autofill.word(this, "autofill_not_saved"));
            }
        }).start();
    }
}
