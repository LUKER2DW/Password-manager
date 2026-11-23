// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.assist.AssistStructure;
import android.app.assist.AssistStructure.ViewNode;
import android.text.InputType;
import android.util.Pair;
import android.view.View;
import android.view.ViewStructure.HtmlInfo;
import android.view.autofill.AutofillId;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A sign-in form as autofill sees it: its username and password fields, and the website it
 * belongs to (in a browser). Fields are recognised by what the app or page says they are
 * (autofill hints, input types, HTML attributes), then by their names; a password field with
 * no named username takes the text field just before it.
 */
final class Fields {
    AutofillId username;
    AutofillId password;
    /** The page's domain in a browser ("accounts.example.com"), else null. */
    String webDomain;
    /** What the fields hold (for "Save to Vault?"). */
    String usernameValue;
    String passwordValue;

    private AutofillId lastText;
    private String lastTextValue;
    private AutofillId beforePassword;
    private String beforePasswordValue;

    static Fields find(AssistStructure structure) {
        Fields fields = new Fields();
        for (int i = 0; i < structure.getWindowNodeCount(); i++) {
            fields.walk(structure.getWindowNodeAt(i).getRootViewNode());
        }
        if (fields.password != null && fields.username == null) {
            fields.username = fields.beforePassword;
            fields.usernameValue = fields.beforePasswordValue;
        }
        return fields;
    }

    /** The fields found, for an offer that covers them all. */
    AutofillId[] ids() {
        List<AutofillId> ids = new ArrayList<>();
        if (username != null) {
            ids.add(username);
        }
        if (password != null) {
            ids.add(password);
        }
        return ids.toArray(new AutofillId[0]);
    }

    private void walk(ViewNode node) {
        String domain = node.getWebDomain();
        if (webDomain == null && domain != null && !domain.isEmpty()) {
            webDomain = domain.toLowerCase(Locale.ROOT);
        }
        AutofillId id = node.getAutofillId();
        if (id != null && node.getAutofillType() == View.AUTOFILL_TYPE_TEXT
                && node.getVisibility() == View.VISIBLE && isTextInput(node)) {
            String value = textOf(node);
            if (isPassword(node)) {
                if (password == null) {
                    password = id;
                    passwordValue = value;
                    beforePassword = lastText;
                    beforePasswordValue = lastTextValue;
                }
            } else if (isUsername(node)) {
                if (username == null) {
                    username = id;
                    usernameValue = value;
                }
            } else {
                lastText = id;
                lastTextValue = value;
            }
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            walk(node.getChildAt(i));
        }
    }

    private static String textOf(ViewNode node) {
        android.view.autofill.AutofillValue value = node.getAutofillValue();
        return value != null && value.isText() ? value.getTextValue().toString() : null;
    }

    private static boolean isTextInput(ViewNode node) {
        HtmlInfo html = node.getHtmlInfo();
        if (html != null) {
            return "input".equalsIgnoreCase(html.getTag());
        }
        String type = node.getClassName();
        return type == null || type.endsWith("EditText") || type.endsWith("TextField")
                || node.getAutofillHints() != null;
    }

    private static boolean isPassword(ViewNode node) {
        if (hinted(node, View.AUTOFILL_HINT_PASSWORD) || hinted(node, "current-password")
                || hinted(node, "new-password")) {
            return true;
        }
        String type = htmlAttribute(node, "type");
        if ("password".equalsIgnoreCase(type)) {
            return true;
        }
        int input = node.getInputType();
        int variation = input & InputType.TYPE_MASK_VARIATION;
        if ((input & InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT) {
            return variation == InputType.TYPE_TEXT_VARIATION_PASSWORD
                    || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
                    || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD;
        }
        return (input & InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_NUMBER
                && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD;
    }

    private static boolean isUsername(ViewNode node) {
        if (hinted(node, View.AUTOFILL_HINT_USERNAME) || hinted(node, View.AUTOFILL_HINT_EMAIL_ADDRESS)
                || hinted(node, "email")) {
            return true;
        }
        String type = htmlAttribute(node, "type");
        if ("email".equalsIgnoreCase(type)) {
            return true;
        }
        String complete = htmlAttribute(node, "autocomplete");
        if (complete != null && (complete.contains("username") || complete.contains("email"))) {
            return true;
        }
        int input = node.getInputType();
        int variation = input & InputType.TYPE_MASK_VARIATION;
        if ((input & InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT
                && (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
                        || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)) {
            return true;
        }
        String names = (node.getIdEntry() + " " + node.getHint() + " "
                + htmlAttribute(node, "name") + " " + htmlAttribute(node, "id"))
                .toLowerCase(Locale.ROOT);
        for (String word : new String[] {"user", "email", "e-mail", "login", "usuário", "usuario"}) {
            if (names.contains(word)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hinted(ViewNode node, String hint) {
        String[] hints = node.getAutofillHints();
        if (hints == null) {
            return false;
        }
        for (String each : hints) {
            if (each != null && each.toLowerCase(Locale.ROOT).contains(hint.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String htmlAttribute(ViewNode node, String name) {
        HtmlInfo html = node.getHtmlInfo();
        if (html == null || html.getAttributes() == null) {
            return null;
        }
        for (Pair<String, String> attribute : html.getAttributes()) {
            if (name.equalsIgnoreCase(attribute.first)) {
                return attribute.second;
            }
        }
        return null;
    }
}
