//! The passkey provider's native methods (`java/org/passwordvault/phone/Passkeys.java`): what
//! Android's Credential Manager asks of the app, through `VaultCredentialService` and
//! `PasskeyActivity` (`vault_mobile::passkeys` decides). Every question brings who asks, and who
//! that stands for is worked out here each time ([`caller`]). With the app running and its
//! vault open, the controller answers on the UI thread; with the vault locked, the vault file
//! is opened here with the device secret a fingerprint released, and the passkeys it reads for
//! one sign-in are kept for a minute at most ([`HELD`]).

use std::{path::PathBuf, ptr, sync::Mutex};

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JString},
    sys::{jboolean, jobjectArray, jstring},
};
use vault_mobile::passkeys::{self, Asker, Caller, Held, Made, Offer, Refusal};
use zeroize::Zeroizing;

use crate::autofill::{ask_app, now, strings, text};
use crate::shell::{bytes, string};

/// The passkeys read with a fingerprint while the vault was locked, until one is used or
/// [`Held::FOR_SECONDS`] pass.
static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());

/// Who the Java side's parts stand for; `None` when no passkey answers there.
fn caller(
    env: &mut JNIEnv,
    app: &JString,
    signers: &JByteArray,
    origin: &JString,
) -> Option<Caller> {
    let signers = bytes(env, signers).unwrap_or_default();
    let (digests, rest) = signers.as_chunks::<32>();
    Caller::of(&Asker {
        app: string(env, app).unwrap_or_default(),
        // Cut short, they are nobody's.
        signers: if rest.is_empty() {
            digests.to_vec()
        } else {
            Vec::new()
        },
        origin: string(env, origin),
    })
}

/// A client data hash the browser sent, or none.
fn sent_hash(env: &mut JNIEnv, hash: &JByteArray) -> Option<Vec<u8>> {
    bytes(env, hash).filter(|hash| !hash.is_empty())
}

/// item, credential, title, account name, display name of each offer.
fn offered(env: &mut JNIEnv, offers: &[Offer]) -> jobjectArray {
    let flat: Vec<&str> = offers
        .iter()
        .flat_map(|o| {
            [
                o.item.as_str(),
                o.credential.as_str(),
                o.title.as_str(),
                o.user_name.as_str(),
                o.display_name.as_str(),
            ]
        })
        .collect();
    strings(env, &flat)
}

/// {answer, title} made, or {"", refusal} not.
fn made(env: &mut JNIEnv, made: Result<Made, Refusal>) -> jobjectArray {
    match made {
        Ok(made) => strings(env, &[made.answer.as_str(), made.title.as_str()]),
        Err(refusal) => {
            let why = match refusal {
                Refusal::Exists => "exists",
                Refusal::Unsupported => "unsupported",
                Refusal::WrongSite => "wrong_site",
                Refusal::BadRequest => "bad_request",
                Refusal::NotKept => "not_kept",
            };
            strings(env, &["", why])
        }
    }
}

/// `Passkeys.privilegedBrowsers`: the browsers Android may tell a page's origin to.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_privilegedBrowsers<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    text(&mut env, &passkeys::privileged_browsers())
}

/// `Passkeys.vaultOpen`: whether the running app has its vault open.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_vaultOpen<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jboolean {
    jboolean::from(ask_app(|c| c.vault_open().then_some(())).is_some())
}

/// `Passkeys.caller`: the page's host or the app's package, for the prompt; null for nobody.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_caller<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    origin: JString<'local>,
) -> jstring {
    match caller(&mut env, &app, &signers, &origin) {
        Some(caller) => text(&mut env, caller.name()),
        None => ptr::null_mut(),
    }
}

/// `Passkeys.offers`: the open vault's passkeys for the request; null while it is locked.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_offers<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    origin: JString<'local>,
    request: JString<'local>,
) -> jobjectArray {
    let Some(to) = caller(&mut env, &app, &signers, &origin) else {
        return ptr::null_mut();
    };
    let request = string(&mut env, &request).unwrap_or_default();
    match ask_app(move |c| c.passkey_offers(&to, &request)) {
        Some(offers) => offered(&mut env, &offers),
        None => ptr::null_mut(),
    }
}

/// `Passkeys.sign`: one passkey of the open vault answers, after the person confirmed.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_sign<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    origin: JString<'local>,
    item: JString<'local>,
    credential: JString<'local>,
    request: JString<'local>,
    hash: JByteArray<'local>,
) -> jstring {
    let Some(to) = caller(&mut env, &app, &signers, &origin) else {
        return ptr::null_mut();
    };
    let item = string(&mut env, &item).unwrap_or_default();
    let credential = string(&mut env, &credential).unwrap_or_default();
    let request = string(&mut env, &request).unwrap_or_default();
    let hash = sent_hash(&mut env, &hash);
    let answer =
        ask_app(move |c| c.passkey_assertion(&to, &item, &credential, &request, hash.as_deref()));
    match answer {
        Some(answer) => text(&mut env, &answer),
        None => ptr::null_mut(),
    }
}

/// `Passkeys.create`: a passkey made in the open vault, after the person confirmed; null while
/// the vault is locked.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_create<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    origin: JString<'local>,
    request: JString<'local>,
    hash: JByteArray<'local>,
) -> jobjectArray {
    let Some(to) = caller(&mut env, &app, &signers, &origin) else {
        return made(&mut env, Err(Refusal::WrongSite));
    };
    let request = string(&mut env, &request).unwrap_or_default();
    let hash = sent_hash(&mut env, &hash);
    match ask_app(move |c| c.passkey_create(&to, &request, hash.as_deref())) {
        Some(result) => made(&mut env, result),
        None => ptr::null_mut(),
    }
}

/// `Passkeys.hold`: the vault locked, opens it with the device secret and keeps the passkeys
/// that answer the request ready for a minute; their offers, or null when it doesn't open.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_hold<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    home: JString<'local>,
    secret: JByteArray<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    origin: JString<'local>,
    request: JString<'local>,
) -> jobjectArray {
    let home = PathBuf::from(string(&mut env, &home).unwrap_or_default());
    let Some(secret) = bytes(&mut env, &secret).map(Zeroizing::new) else {
        return ptr::null_mut();
    };
    let Some(to) = caller(&mut env, &app, &signers, &origin) else {
        return ptr::null_mut();
    };
    let request = string(&mut env, &request).unwrap_or_default();
    let now = now();
    let Some((held, offers)) = Held::open(&home, &secret, &to, &request, now) else {
        return ptr::null_mut();
    };
    if let Ok(mut kept) = HELD.lock() {
        kept.retain(|h| h.fresh(now));
        kept.push(held);
    }
    offered(&mut env, &offers)
}

/// `Passkeys.signHeld`: one of the passkeys `hold` keeps answers; they all go once one has.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_signHeld<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    origin: JString<'local>,
    item: JString<'local>,
    credential: JString<'local>,
    request: JString<'local>,
    hash: JByteArray<'local>,
) -> jstring {
    let Some(to) = caller(&mut env, &app, &signers, &origin) else {
        return ptr::null_mut();
    };
    let item = string(&mut env, &item).unwrap_or_default();
    let credential = string(&mut env, &credential).unwrap_or_default();
    let request = string(&mut env, &request).unwrap_or_default();
    let hash = sent_hash(&mut env, &hash);
    let now = now();
    let answer = HELD.lock().ok().and_then(|mut kept| {
        let answer = kept.iter().find_map(|held| {
            held.assertion(&to, &item, &credential, &request, hash.as_deref(), now)
        });
        if answer.is_some() {
            kept.clear();
        } else {
            kept.retain(|h| h.fresh(now));
        }
        answer
    });
    match answer {
        Some(answer) => text(&mut env, &answer),
        None => ptr::null_mut(),
    }
}

/// `Passkeys.createWithSecret`: the vault locked, opens the vault file with the device secret,
/// makes the passkey in it and saves the file.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_Passkeys_createWithSecret<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    home: JString<'local>,
    secret: JByteArray<'local>,
    app: JString<'local>,
    signers: JByteArray<'local>,
    origin: JString<'local>,
    request: JString<'local>,
    hash: JByteArray<'local>,
) -> jobjectArray {
    let home = PathBuf::from(string(&mut env, &home).unwrap_or_default());
    let Some(secret) = bytes(&mut env, &secret).map(Zeroizing::new) else {
        return made(&mut env, Err(Refusal::NotKept));
    };
    let Some(to) = caller(&mut env, &app, &signers, &origin) else {
        return made(&mut env, Err(Refusal::WrongSite));
    };
    let request = string(&mut env, &request).unwrap_or_default();
    let hash = sent_hash(&mut env, &hash);
    let result =
        passkeys::create_with_secret(&home, &secret, &to, &request, hash.as_deref(), now());
    made(&mut env, result)
}
