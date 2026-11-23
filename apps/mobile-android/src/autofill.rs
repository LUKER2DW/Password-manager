//! Autofill's native methods (`java/org/passwordvault/phone/Autofill.java`): what the autofill
//! service and its activity ask of the app (`vault_mobile::autofill` decides). With the app
//! running, a question goes to the controller on the UI thread and its answer comes back
//! within two seconds; without it (Android started the process for autofill alone) the vault
//! counts as locked, and only fingerprint unlock or the drop box are used.

use std::{
    path::PathBuf,
    ptr,
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject, JString},
    sys::{jboolean, jbyteArray, jobjectArray, jstring},
};
use vault_mobile::{Controller, autofill};
use zeroize::Zeroizing;

use crate::shell::{CONTROLLER, bytes, string};

/// How long a question to the running app may take.
const WAIT: Duration = Duration::from_secs(2);

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Asks the running app (on its UI thread) and waits for the answer; `None` when the app isn't
/// running, its vault is locked, or it doesn't answer in time.
fn ask_app<T: Send + 'static>(
    ask: impl FnOnce(&Controller) -> Option<T> + Send + 'static,
) -> Option<T> {
    let (answer, answered) = mpsc::channel();
    slint::invoke_from_event_loop(move || {
        let found = CONTROLLER
            .with(|current| current.borrow().upgrade())
            .and_then(|controller| ask(&controller));
        let _ = answer.send(found);
    })
    .ok()?;
    answered.recv_timeout(WAIT).ok().flatten()
}

/// A Java `String[]` of `items`, or null.
fn strings(env: &mut JNIEnv, items: &[&str]) -> jobjectArray {
    let made = (|| -> jni::errors::Result<jobjectArray> {
        let length = i32::try_from(items.len()).unwrap_or(i32::MAX);
        let array = env.new_object_array(length, "java/lang/String", JObject::null())?;
        for (index, item) in items.iter().enumerate() {
            let text = env.new_string(item)?;
            env.set_object_array_element(&array, i32::try_from(index).unwrap_or(0), &text)?;
            env.delete_local_ref(text)?;
        }
        Ok(array.into_raw())
    })();
    made.unwrap_or(ptr::null_mut())
}

fn text(env: &mut JNIEnv, value: &str) -> jstring {
    env.new_string(value)
        .map_or(ptr::null_mut(), JString::into_raw)
}

/// `Autofill.openLogins`: id, title, username of each login for the place, from the open vault.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_openLogins<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    domain: JString<'local>,
    app: JString<'local>,
) -> jobjectArray {
    let domain = string(&mut env, &domain);
    let app = string(&mut env, &app).unwrap_or_default();
    let Some(logins) = ask_app(move |c| c.autofill_logins(domain.as_deref(), &app)) else {
        return ptr::null_mut();
    };
    let flat: Vec<&str> = logins
        .iter()
        .flat_map(|l| [l.id.as_str(), l.title.as_str(), l.username.as_str()])
        .collect();
    strings(&mut env, &flat)
}

/// `Autofill.openLogin`: username and password of one login of the open vault, after the
/// person confirmed (the activity asked).
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_openLogin<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    item: JString<'local>,
    domain: JString<'local>,
    app: JString<'local>,
) -> jobjectArray {
    let item = string(&mut env, &item).unwrap_or_default();
    let domain = string(&mut env, &domain);
    let app = string(&mut env, &app).unwrap_or_default();
    let Some(login) = ask_app(move |c| c.autofill_login(&item, domain.as_deref(), &app)) else {
        return ptr::null_mut();
    };
    strings(
        &mut env,
        &[login.username.as_str(), login.password.as_str()],
    )
}

/// `Autofill.lockedVault`: the vault with a fresh fingerprint unlock, while the app is locked.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_lockedVault<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    home: JString<'local>,
) -> jstring {
    let home = PathBuf::from(string(&mut env, &home).unwrap_or_default());
    match autofill::locked_unlock(&home, now()) {
        Some((id, _)) => text(&mut env, &id),
        None => ptr::null_mut(),
    }
}

/// `Autofill.lockedSealed`: that vault's device secret, as the secure hardware sealed it.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_lockedSealed<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    home: JString<'local>,
) -> jbyteArray {
    let home = PathBuf::from(string(&mut env, &home).unwrap_or_default());
    match autofill::locked_unlock(&home, now()) {
        Some((_, sealed)) => env
            .byte_array_from_slice(&sealed)
            .map_or(ptr::null_mut(), JByteArray::into_raw),
        None => ptr::null_mut(),
    }
}

/// `Autofill.openWithSecret`: title, username, password of each login for the place, opening
/// the vault with the device secret the fingerprint released.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_openWithSecret<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    home: JString<'local>,
    secret: JByteArray<'local>,
    domain: JString<'local>,
    app: JString<'local>,
) -> jobjectArray {
    let home = PathBuf::from(string(&mut env, &home).unwrap_or_default());
    let Some(secret) = bytes(&mut env, &secret).map(Zeroizing::new) else {
        return ptr::null_mut();
    };
    let domain = string(&mut env, &domain);
    let app = string(&mut env, &app).unwrap_or_default();
    let Some(logins) = autofill::open_with_secret(&home, &secret, domain.as_deref(), &app, now())
    else {
        return ptr::null_mut();
    };
    let flat: Vec<&str> = logins
        .iter()
        .flat_map(|l| [l.title.as_str(), l.username.as_str(), l.password.as_str()])
        .collect();
    strings(&mut env, &flat)
}

/// `Autofill.suggest`: a strong password from the app's generator.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_suggest<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    match autofill::suggest() {
        Some(password) => text(&mut env, &password),
        None => ptr::null_mut(),
    }
}

/// `Autofill.save`: "Save to Vault?" from another app: into the open vault, or, while it is
/// locked, into its drop box for the next unlock.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_save<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    home: JString<'local>,
    domain: JString<'local>,
    app: JString<'local>,
    username: JString<'local>,
    password: JString<'local>,
) -> jboolean {
    let home = PathBuf::from(string(&mut env, &home).unwrap_or_default());
    let domain = string(&mut env, &domain);
    let app = string(&mut env, &app).unwrap_or_default();
    let username = string(&mut env, &username).unwrap_or_default();
    let password = Zeroizing::new(string(&mut env, &password).unwrap_or_default());
    let saved_open = {
        let (domain, app, username, password) = (
            domain.clone(),
            app.clone(),
            username.clone(),
            password.clone(),
        );
        ask_app(move |c| {
            c.autofill_save(domain.as_deref(), &app, &username, &password)
                .then_some(())
        })
        .is_some()
    };
    let saved =
        saved_open || autofill::keep_locked(&home, domain.as_deref(), &app, &username, &password);
    jboolean::from(saved)
}
