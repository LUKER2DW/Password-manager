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
import java.util.Objects;

/**
 * A sign-in form as autofill sees it: its username and password fields, and the page they are
 * in (in a browser). Fields are recognised by what the app or page says they are (autofill
 * hints, input types, HTML attributes), then by their names; a password field with no named
 * username takes the text field just before it.
 *
 * A form's fields are all of one origin: the app's own, or one web view's fields of one domain
 * and scheme. A screen may show several (a page with another site's frame in it, an app's own
 * fields next to a web page); a domain counts only for the fields under the node that gives it,
 * and fields of two origins are never one form. A form in a frame of another site than the
 * page around it ({@link #framedByAnotherSite}) gets no offer and saves nothing (AutoFail,
 * USENIX Security 2026: the person sees the page, not the frame).
 */
final class Fields {
    AutofillId username;
    AutofillId password;
    /**
     * The domain of the page the fields are in ("accounts.example.com"), as the web view around
     * them gives it ("" for a page with none); null for the app's own fields.
     */
    String webDomain;
    /** The page's scheme, when the web view gives it ("https"). */
    String webScheme;
    /**
     * The domain of the top page of the web view the fields are in ("" when it gives none):
     * {@link #webDomain} itself unless the fields are in a frame of another domain.
     */
    String topDomain;
    /** What the fields hold (for "Save to Vault?"). */
    String usernameValue;
    String passwordValue;

    /** The outermost node of the web view the fields are in; null for the app's own. */
    private ViewNode web;
    private AutofillId lastText;
    private String lastTextValue;
    private AutofillId beforePassword;
    private String beforePasswordValue;

    /**
     * The form to fill: the one with the focus; else (the focus is on no sign-in form) the first
     * with a password, else with a username. Without any, one without fields.
     */
    static Fields find(AssistStructure structure) {
        Finder finder = new Finder(structure);
        if (finder.focused != null && finder.focused.signsIn()) {
            return finder.focused;
        }
        Fields found = null;
        for (Fields form : finder.forms) {
            if (form.password != null) {
                return form;
            }
            if (found == null && form.signsIn()) {
                found = form;
            }
        }
        return found == null ? new Fields() : found;
    }

    /** The form whose password field is {@code password}, or null when it isn't there any more. */
    static Fields holding(AssistStructure structure, AutofillId password) {
        for (Fields form : new Finder(structure).forms) {
            if (password.equals(form.password)) {
                return form;
            }
        }
        return null;
    }

    /** Every form on a screen, one for each origin, and which has the focus. */
    private static final class Finder {
        final List<Fields> forms = new ArrayList<>();
        Fields focused;

        Finder(AssistStructure structure) {
            Fields own = new Fields();
            forms.add(own);
            for (int i = 0; i < structure.getWindowNodeCount(); i++) {
                walk(structure.getWindowNodeAt(i).getRootViewNode(), own);
            }
            for (Fields form : forms) {
                form.finish();
            }
        }

        /** {@code around}: the form the fields around this node belong to. */
        private void walk(ViewNode node, Fields around) {
            Fields here = around;
            String domain = node.getWebDomain();
            String scheme = node.getWebScheme();
            if (domain != null || scheme != null) {
                // This node, and what is under it, is a web page (or another page inside one).
                // One with a scheme and no host (a "data:" page) is nobody's site: neither the
                // app's own fields nor the page's around it.
                String page = domain == null ? "" : domain;
                here = page(around.web == null ? node : around.web, page, scheme,
                        around.web == null ? page : around.topDomain);
            }
            if (node.isFocused()) {
                // The innermost one: a web view has the focus along with the field in it.
                focused = here;
            }
            here.take(node);
            for (int i = 0; i < node.getChildCount(); i++) {
                walk(node.getChildAt(i), here);
            }
        }

        private Fields page(ViewNode web, String domain, String scheme, String top) {
            domain = domain.toLowerCase(Locale.ROOT);
            scheme = scheme == null ? null : scheme.toLowerCase(Locale.ROOT);
            for (Fields form : forms) {
                if (form.web == web && domain.equals(form.webDomain)
                        && Objects.equals(scheme, form.webScheme)) {
                    return form;
                }
            }
            Fields form = new Fields();
            form.web = web;
            form.webDomain = domain;
            form.webScheme = scheme;
            form.topDomain = top.toLowerCase(Locale.ROOT);
            forms.add(form);
            return form;
        }
    }

    /**
     * The fields are in a frame whose domain isn't the top page's, nor of the same site
     * ({@code Autofill.sameSite}: the same registrable domain, as a sign-in served from the
     * site's own accounts host). When the web view names no top page, it can't be told, and
     * the frame's own domain is all there is.
     */
    boolean framedByAnotherSite() {
        return webDomain != null && topDomain != null && !topDomain.isEmpty()
                && !topDomain.equals(webDomain) && !Autofill.sameSite(topDomain, webDomain);
    }

    private boolean signsIn() {
        return password != null || username != null;
    }

    private void finish() {
        if (password != null && username == null) {
            username = beforePassword;
            usernameValue = beforePasswordValue;
        }
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

    /** Takes the node's field into this form, if it is one that counts. */
    private void take(ViewNode node) {
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
