// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * Where the system's installer answers ({@link Updates}). Not exported: only this app's own
 * PendingIntent, held by the installer, leads here, unlike the activity, which any app can send
 * an intent to.
 */
public class InstallReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent answer) {
        if (Updates.expected(answer)) {
            VaultActivity.installAnswered(answer);
        }
    }
}
