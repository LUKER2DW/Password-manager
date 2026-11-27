//! Autofill's native methods (`java/org/passwordvault/phone/Autofill.java`): what the autofill
//! service and its activity ask of the app (`vault_mobile::autofill` decides). Every question
//! brings who asks (`Place.java`), and who that stands for is worked out here each time
//! ([`recipient`]): nothing is answered to nobody. With the app running, a question goes to the
//! controller on the UI thread and its answer comes back within two seconds; without it
//! (Android started the process for autofill alone) the vault counts as locked, and only
//! fingerprint unlock or the drop box are used.

use std::{
    path::PathBuf,
    ptr,
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject, JString},
    sys::{jboolean, jbyteArray, jint, jobjectArray, jstring},
};
use vault_mobile::{
    Controller,
    autofill::{self, Asker, Kept, Recipient},
};
use zeroize::Zeroizing;

use crate::shell::{CONTROLLER, bytes, string};

/// How long a question to the running app may take.
const WAIT: Duration = Duration::from_secs(2);

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Asks the running app (on its UI thread) and waits for the answer; `None` when the app isn't
/// running, its vault is locked, or it doesn't answer in time.
pub(crate) fn ask_app<T: Send + 'static>(
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
pub(crate) fn strings(env: &mut JNIEnv, items: &[&str]) -> jobjectArray {
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

pub(crate) fn text(env: &mut JNIEnv, value: &str) -> jstring {
    env.new_string(value)
        .map_or(ptr::null_mut(), JString::into_raw)
}

/// Who a place's parts (`Place.java`) stand for; `None` when nothing is offered or saved there.
fn recipient(
    env: &mut JNIEnv,
    app: &JString,
    signers: &JByteArray,
    browser: jboolean,
    domain: &JString,
    scheme: &JString,
) -> Option<Recipient> {
    let signers = bytes(env, signers).unwrap_or_default();
    let (digests, rest) = signers.as_chunks::<32>();
    Recipient::of(&Asker {
        app: string(env, app).unwrap_or_default(),
        // Cut short, they are nobody's.
        signers: if rest.is_empty() {
            digests.to_vec()
        } else {
            Vec::new()
        },
        browser: browser != 0,
        domain: string(env, domain),
        scheme: string(env, scheme),
    })
}

/// `Autofill.recipient`: the website or app the place stands for, for the prompt; null when
/// nothing is offered or saved there.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_recipient<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    browser: jboolean,
    domain: JString<'local>,
    scheme: JString<'local>,
) -> jstring {
    match recipient(&mut env, &app, &signers, browser, &domain, &scheme) {
        Some(to) => text(&mut env, to.name()),
        None => ptr::null_mut(),
    }
}

/// `Autofill.openLogins`: id, title, username of each login for the place, from the open vault.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_openLogins<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    browser: jboolean,
    domain: JString<'local>,
    scheme: JString<'local>,
) -> jobjectArray {
    let Some(to) = recipient(&mut env, &app, &signers, browser, &domain, &scheme) else {
        return ptr::null_mut();
    };
    let Some(logins) = ask_app(move |c| c.autofill_logins(&to)) else {
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
    app: JString<'local>,
    signers: JByteArray<'local>,
    browser: jboolean,
    domain: JString<'local>,
    scheme: JString<'local>,
) -> jobjectArray {
    let item = string(&mut env, &item).unwrap_or_default();
    let Some(to) = recipient(&mut env, &app, &signers, browser, &domain, &scheme) else {
        return ptr::null_mut();
    };
    let Some(login) = ask_app(move |c| c.autofill_login(&item, &to)) else {
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
    app: JString<'local>,
    signers: JByteArray<'local>,
    browser: jboolean,
    domain: JString<'local>,
    scheme: JString<'local>,
) -> jobjectArray {
    let home = PathBuf::from(string(&mut env, &home).unwrap_or_default());
    let Some(secret) = bytes(&mut env, &secret).map(Zeroizing::new) else {
        return ptr::null_mut();
    };
    let Some(to) = recipient(&mut env, &app, &signers, browser, &domain, &scheme) else {
        return ptr::null_mut();
    };
    let Some(logins) = autofill::open_with_secret(&home, &secret, &to, now()) else {
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

/// `Autofill.NOT_SAVED`, `SAVED` and `SAVED_BESIDE`: what `Autofill.save` answers.
const NOT_SAVED: jint = 0;
const SAVED: jint = 1;
const SAVED_BESIDE: jint = 2;

/// `Autofill.save`: "Save to Vault?" from another app: into the open vault, or, while it is
/// locked, into its drop box for the next unlock.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Autofill_save<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    home: JString<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    browser: jboolean,
    domain: JString<'local>,
    scheme: JString<'local>,
    username: JString<'local>,
    password: JString<'local>,
) -> jint {
    let home = PathBuf::from(string(&mut env, &home).unwrap_or_default());
    let Some(from) = recipient(&mut env, &app, &signers, browser, &domain, &scheme) else {
        return NOT_SAVED;
    };
    let username = string(&mut env, &username).unwrap_or_default();
    let password = Zeroizing::new(string(&mut env, &password).unwrap_or_default());
    let saved_open = {
        let (from, username, password) = (from.clone(), username.clone(), password.clone());
        ask_app(move |c| c.autofill_save(&from, &username, &password))
    };
    match saved_open {
        Some(Kept::AddedBeside) => SAVED_BESIDE,
        Some(Kept::Same | Kept::Replaced | Kept::Added) => SAVED,
        None if autofill::keep_locked(&home, &from, &username, &password) => SAVED,
        None => NOT_SAVED,
    }
}
