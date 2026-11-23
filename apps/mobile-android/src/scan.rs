//! The QR code of an invite, read by Google's code scanner through the activity
//! (`VaultActivity.scanCode`, Play services' own camera screen): the text comes back to
//! [`Java_org_passwordvault_phone_VaultActivity_scanned`] and goes on to the controller.

use jni::{
    JNIEnv,
    objects::{JClass, JString, JValue},
    sys::jint,
};

use crate::shell::{on_ui, string, with_activity};

/// Opens the code scanner; `purpose` says where the line goes (`vault_mobile` `scan::*`).
pub(crate) fn scan(purpose: i32) -> Result<(), String> {
    with_activity(|env, activity| {
        env.call_method(activity, "scanCode", "(I)V", &[JValue::Int(purpose)])
            .map(|_| ())
    })
}

/// `VaultActivity.scanned`: the text of the QR code read, or none (cancelled, or why not).
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_VaultActivity_scanned<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    purpose: jint,
    text: JString<'local>,
    error: JString<'local>,
) {
    let text = string(&mut env, &text);
    let error = string(&mut env, &error);
    on_ui(move |controller| match (text, error) {
        (Some(text), _) => controller.code_scanned(purpose, &text),
        (None, Some(error)) => controller.scan_failed(&error),
        (None, None) => {}
    });
}
