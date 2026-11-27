// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.os.Build;
import android.view.View;
import android.view.Window;

/**
 * What every window of the app gets, from its first frame (VaultActivity, AutofillActivity,
 * PasskeyActivity): no other app's overlay drawn over it while it shows, and nothing in it for
 * an accessibility service that isn't an accessibility tool.
 *
 * Another app with the "display over other apps" permission could draw a window over the app's
 * that looks like part of it (a false unlock screen, a button laid over the real one) or that
 * the person's taps go through. Android hides every such overlay while one of these windows is
 * on screen (the HIDE_OVERLAY_WINDOWS permission, which Android grants without asking); the
 * system's own windows (its prompts, the keyboard, the status bar) still show. The overlays that
 * remain trusted (an accessibility tool's, the system's) are those Android lets taps through
 * anyway.
 *
 * The app's screen is one surface its Rust library draws (NativeActivity), so its touches never
 * pass through Android's views, where {@code filterTouchesWhenObscured} would drop those that
 * came through another window: hiding the overlays is what keeps such taps away. Android 12, the
 * oldest the app installs on, also blocks by itself taps that pass through another app's
 * window (all but an overlay drawn at most 80% opaque, which is hidden here).
 */
final class Shield {
    private Shield() {}

    static void guard(Window window) {
        window.setHideOverlayWindows(true);
        // Android 14: only the services that say they are accessibility tools (a screen reader)
        // may read the window or act in it.
        if (Build.VERSION.SDK_INT >= 34) {
            window.getDecorView().setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES);
        }
    }
}
