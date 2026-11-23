//! The clipboard on Android, through the system's `ClipboardManager` (JNI). A secret is marked
//! sensitive (`android.content.extra.IS_SENSITIVE`), so Android 13+ doesn't show it in the
//! copy preview and keyboards don't offer it as a suggestion.
//!
//! The text passes through a Java string on its way to the clipboard; that copy belongs to the
//! system and can't be wiped from here (THREAT_MODEL.md, the clipboard).

use anyhow::{Context, Result, anyhow};
use jni::{
    JNIEnv, JavaVM,
    objects::{JObject, JString, JValue},
};
use zeroize::Zeroizing;

/// Runs `f` with the JNI environment of this thread and the system's clipboard manager.
#[allow(unsafe_code)]
fn with_clipboard<T>(f: impl FnOnce(&mut JNIEnv, &JObject, &JObject) -> Result<T>) -> Result<T> {
    let context = ndk_context::android_context();
    // SAFETY: the pointer is the process's JavaVM, registered by the activity glue (Slint's
    // Android backend) before any app code runs, and valid for the life of the process.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) }.context("the Java VM")?;
    let mut env = vm
        .attach_current_thread()
        .context("attaching to the Java VM")?;
    // SAFETY: a global reference to the app's context (the Application), kept by the glue for
    // the life of the process; wrapping it doesn't take ownership (a `JObject` deletes nothing
    // on drop). Only `Context` methods are called on it.
    let context = unsafe { JObject::from_raw(context.context().cast()) };
    env.with_local_frame(16, |env| -> Result<T> {
        let result = (|| {
            let name = env.new_string("clipboard")?;
            let manager = env
                .call_method(
                    &context,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[JValue::Object(&name)],
                )?
                .l()?;
            if manager.is_null() {
                return Err(anyhow!("no clipboard service"));
            }
            f(env, &context, &manager)
        })();
        // A Java exception left pending makes the next JNI call abort the app.
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result
    })
}

fn set(text: &str, sensitive: bool) -> Result<()> {
    with_clipboard(|env, _, manager| {
        let label = env.new_string("")?;
        let value = env.new_string(text)?;
        let clip = env
            .call_static_method(
                "android/content/ClipData",
                "newPlainText",
                "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;",
                &[JValue::Object(&label), JValue::Object(&value)],
            )?
            .l()?;
        if sensitive {
            let description = env
                .call_method(
                    &clip,
                    "getDescription",
                    "()Landroid/content/ClipDescription;",
                    &[],
                )?
                .l()?;
            let extras = env.new_object("android/os/PersistableBundle", "()V", &[])?;
            let key = env.new_string("android.content.extra.IS_SENSITIVE")?;
            env.call_method(
                &extras,
                "putBoolean",
                "(Ljava/lang/String;Z)V",
                &[JValue::Object(&key), JValue::Bool(1)],
            )?;
            env.call_method(
                &description,
                "setExtras",
                "(Landroid/os/PersistableBundle;)V",
                &[JValue::Object(&extras)],
            )?;
        }
        env.call_method(
            manager,
            "setPrimaryClip",
            "(Landroid/content/ClipData;)V",
            &[JValue::Object(&clip)],
        )?;
        Ok(())
    })
    .context("copying to the clipboard")
}

pub fn copy_secret(text: &str) -> Result<()> {
    set(text, true)
}

pub fn copy_plain(text: &str) -> Result<()> {
    set(text, false)
}

fn get() -> Option<Zeroizing<String>> {
    with_clipboard(|env, activity, manager| {
        let clip = env
            .call_method(
                manager,
                "getPrimaryClip",
                "()Landroid/content/ClipData;",
                &[],
            )?
            .l()?;
        if clip.is_null() {
            return Ok(None);
        }
        let item = env
            .call_method(
                &clip,
                "getItemAt",
                "(I)Landroid/content/ClipData$Item;",
                &[JValue::Int(0)],
            )?
            .l()?;
        let text = env
            .call_method(
                &item,
                "coerceToText",
                "(Landroid/content/Context;)Ljava/lang/CharSequence;",
                &[JValue::Object(activity)],
            )?
            .l()?;
        if text.is_null() {
            return Ok(None);
        }
        let string: JString = env
            .call_method(&text, "toString", "()Ljava/lang/String;", &[])?
            .l()?
            .into();
        let value: String = env.get_string(&string)?.into();
        Ok(Some(Zeroizing::new(value)))
    })
    .ok()
    .flatten()
}

pub fn paste_text() -> Option<Zeroizing<String>> {
    let text = get()?;
    let first = text.lines().next().unwrap_or_default();
    Some(Zeroizing::new(first.to_owned()))
}

pub fn clear_if(expected: &str) -> bool {
    let still_ours = get().is_some_and(|current| current.as_str() == expected);
    still_ours
        && with_clipboard(|env, _, manager| {
            env.call_method(manager, "clearPrimaryClip", "()V", &[])?;
            Ok(())
        })
        .is_ok()
}
