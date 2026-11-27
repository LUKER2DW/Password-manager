// SPDX-License-Identifier: GPL-3.0-or-later
package org.passwordvault.phone;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.concurrent.Executor;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The phone's own unlock for a vault: one AES-256-GCM key per vault in the Android Keystore
 * (StrongBox when the phone has it), usable only right after the person proves it is them.
 * From Android 11 that is a strong biometric (fingerprint, face) or the phone's screen lock
 * (PIN, pattern, password), as the person picks in the system's prompt; before Android 11, a
 * strong biometric only. Android retires the key when a new fingerprint or face is added. It
 * seals the device secret the app's Rust side hands over (docs/spec/CRYPTO.md §3.1); the
 * vault key itself never comes here.
 *
 * Keys made before the screen lock was accepted keep their old rule (a biometric only) until
 * the person turns the phone's unlock off and on again.
 *
 * Answers: the bytes, or an error: "" when the person cancelled or chose the master password,
 * "invalidated" when the key is gone (fingerprints changed), else what went wrong.
 */
final class Biometrics {
    private static final String PREFIX = "vault-unlock-";
    private static final String STORE = "AndroidKeyStore";
    private static final int IV = 12;
    interface Answer {
        void done(byte[] data, String error);
    }

    private interface Step {
        byte[] run(Cipher cipher) throws Exception;
    }

    private Biometrics() {}

    /** A strong biometric (Android's Class 3) or a screen lock is set up. */
    static boolean available(Context context) {
        BiometricManager manager = context.getSystemService(BiometricManager.class);
        if (manager == null) {
            return false;
        }
        int result = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG
                | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        return result == BiometricManager.BIOMETRIC_SUCCESS;
    }

    /** Makes the vault's key, asks for the person and seals {@code secret} (wiped after). */
    static void seal(Activity activity, String vaultId, byte[] secret, String title,
            String subtitle, String cancel, Answer answer) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, newKey(vaultId));
            prompt(activity, cipher, true, title, subtitle, cancel, c -> {
                byte[] iv = c.getIV();
                byte[] sealed = c.doFinal(secret);
                byte[] out = new byte[iv.length + sealed.length];
                System.arraycopy(iv, 0, out, 0, iv.length);
                System.arraycopy(sealed, 0, out, iv.length, sealed.length);
                return out;
            }, answer, secret);
        } catch (Exception e) {
            Arrays.fill(secret, (byte) 0);
            answer.done(null, String.valueOf(e.getMessage()));
        }
    }

    /** Asks for the person and opens what {@link #seal} sealed. */
    static void open(Activity activity, String vaultId, byte[] sealed, String title,
            String subtitle, String cancel, Answer answer) {
        try {
            KeyStore store = KeyStore.getInstance(STORE);
            store.load(null);
            SecretKey key = (SecretKey) store.getKey(PREFIX + vaultId, null);
            if (key == null || sealed.length <= IV) {
                answer.done(null, "invalidated");
                return;
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, sealed, 0, IV));
            prompt(activity, cipher, takesScreenLock(key), title, subtitle, cancel,
                    c -> c.doFinal(sealed, IV, sealed.length - IV), answer, null);
        } catch (KeyPermanentlyInvalidatedException e) {
            forget(vaultId);
            answer.done(null, "invalidated");
        } catch (Exception e) {
            answer.done(null, String.valueOf(e.getMessage()));
        }
    }

    /**
     * Whether this key was made to take the screen lock too: every key made on Android 11 or
     * later; one made before (on a phone updated since) takes a biometric only.
     */
    private static boolean takesScreenLock(SecretKey key) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), STORE);
            KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
            return (info.getUserAuthenticationType() & KeyProperties.AUTH_DEVICE_CREDENTIAL) != 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Asks for a fingerprint (or face) or the phone's own lock (PIN, pattern, password) before
     * a fill. Answers an empty array once confirmed; "no_lock" when the phone has no screen
     * lock at all.
     */
    static void confirm(Activity activity, String title, String subtitle, String cancel,
            Answer answer) {
        KeyguardManager keyguard = activity.getSystemService(KeyguardManager.class);
        if (keyguard == null || !keyguard.isDeviceSecure()) {
            answer.done(null, "no_lock");
            return;
        }
        Executor main = activity.getMainExecutor();
        BiometricPrompt.Builder builder = new BiometricPrompt.Builder(activity).setTitle(title);
        if (subtitle != null && !subtitle.isEmpty()) {
            builder.setSubtitle(subtitle);
        }
        builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        builder.build().authenticate(new CancellationSignal(), main,
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        answer.done(new byte[0], null);
                    }

                    @Override
                    public void onAuthenticationError(int code, CharSequence message) {
                        boolean cancelled = code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED
                                || code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED;
                        answer.done(null, cancelled ? "" : String.valueOf(message));
                    }
                });
    }

    /** Deletes the vault's key. */
    static void forget(String vaultId) {
        try {
            KeyStore store = KeyStore.getInstance(STORE);
            store.load(null);
            store.deleteEntry(PREFIX + vaultId);
        } catch (Exception e) {
            // Nothing to delete.
        }
    }

    private static SecretKey newKey(String vaultId) throws Exception {
        forget(vaultId);
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(PREFIX + vaultId,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                // Every use needs its own check: a strong biometric or the screen lock.
                .setUserAuthenticationParameters(0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE);
        try {
            spec.setIsStrongBoxBacked(true);
            generator.init(spec.build());
            return generator.generateKey();
        } catch (Exception e) {
            // No StrongBox on this phone: the Keystore's own secure hardware.
            spec.setIsStrongBoxBacked(false);
            generator.init(spec.build());
            return generator.generateKey();
        }
    }

    /**
     * The system's prompt around {@code cipher}. With {@code screenLock} it offers the phone's
     * PIN, pattern or password next to the biometric (Android then draws its own way out, so
     * there is no button of ours); without, a biometric only and our cancel button.
     */
    private static void prompt(Activity activity, Cipher cipher, boolean screenLock, String title,
            String subtitle, String cancel, Step step, Answer answer, byte[] wipe) {
        Executor main = activity.getMainExecutor();
        BiometricPrompt.Builder builder = new BiometricPrompt.Builder(activity).setTitle(title);
        if (subtitle != null && !subtitle.isEmpty()) {
            builder.setSubtitle(subtitle);
        }
        builder.setConfirmationRequired(false);
        if (screenLock) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                    | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        } else {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
            builder.setNegativeButton(cancel, main, (dialog, which) -> {
                wipe(wipe);
                answer.done(null, "");
            });
        }
        builder.build().authenticate(new BiometricPrompt.CryptoObject(cipher),
                new CancellationSignal(), main, new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        try {
                            answer.done(step.run(result.getCryptoObject().getCipher()), null);
                        } catch (Exception e) {
                            answer.done(null, String.valueOf(e.getMessage()));
                        } finally {
                            wipe(wipe);
                        }
                    }

                    @Override
                    public void onAuthenticationError(int code, CharSequence message) {
                        wipe(wipe);
                        boolean cancelled = code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED
                                || code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED;
                        answer.done(null, cancelled ? "" : String.valueOf(message));
                    }
                });
    }

    private static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
