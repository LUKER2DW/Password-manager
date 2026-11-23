//! What only Android does, for the controller (`vault_mobile::System`), through the activity
//! (`java/org/passwordvault/phone/VaultActivity.java` and `Biometrics.java`): fingerprint
//! unlock, keeping the app out of screenshots, Android's autofill settings, installing an
//! update. Answers that need the person come back to the native methods at the end of this
//! file, and go on to the controller on the UI thread.

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JString, JValue},
    sys::{jboolean, jint},
};
use vault_mobile::{PromptWords, System};
use zeroize::Zeroizing;

use crate::shell::{bytes, on_ui, string, with_activity};

/// The activity, as the controller's `System`.
#[derive(Debug, Default)]
pub(crate) struct AndroidSystem;

impl AndroidSystem {
    fn prompt(
        &self,
        method: &str,
        vault_id: &str,
        data: &[u8],
        words: &PromptWords,
    ) -> Result<(), String> {
        with_activity(|env, activity| {
            let id = env.new_string(vault_id)?;
            let data = env.byte_array_from_slice(data)?;
            let title = env.new_string(&words.title)?;
            let detail = env.new_string(&words.detail)?;
            let cancel = env.new_string(&words.cancel)?;
            env.call_method(
                activity,
                method,
                "(Ljava/lang/String;[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(&id),
                    JValue::Object(&data),
                    JValue::Object(&title),
                    JValue::Object(&detail),
                    JValue::Object(&cancel),
                ],
            )
            .map(|_| ())
        })
    }

    fn text(&self, method: &str) -> Option<String> {
        with_activity(|env, activity| {
            let value = env
                .call_method(activity, method, "()Ljava/lang/String;", &[])?
                .l()?;
            Ok(string(env, &JString::from(value)))
        })
        .ok()
        .flatten()
    }
}

impl System for AndroidSystem {
    fn biometrics(&self) -> bool {
        with_activity(|env, activity| {
            env.call_method(activity, "biometricsAvailable", "()Z", &[])?
                .z()
        })
        .unwrap_or(false)
    }

    fn seal_with_biometrics(
        &self,
        vault_id: &str,
        secret: &[u8],
        words: &PromptWords,
    ) -> Result<(), String> {
        self.prompt("sealWithBiometrics", vault_id, secret, words)
    }

    fn open_with_biometrics(
        &self,
        vault_id: &str,
        sealed: &[u8],
        words: &PromptWords,
    ) -> Result<(), String> {
        self.prompt("openWithBiometrics", vault_id, sealed, words)
    }

    fn forget_biometrics(&self, vault_id: &str) {
        let _ = with_activity(|env, activity| {
            let id = env.new_string(vault_id)?;
            env.call_method(
                activity,
                "forgetBiometrics",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&id)],
            )
            .map(|_| ())
        });
    }

    fn keep_off_screenshots(&self, on: bool) {
        let _ = with_activity(|env, activity| {
            env.call_method(activity, "setSecure", "(Z)V", &[JValue::Bool(on.into())])
                .map(|_| ())
        });
    }

    fn autofill(&self) -> Option<bool> {
        let state = with_activity(|env, activity| {
            env.call_method(activity, "autofillState", "()I", &[])?.i()
        })
        .unwrap_or(-1);
        match state {
            1 => Some(true),
            0 => Some(false),
            _ => None,
        }
    }

    fn open_autofill_settings(&self) {
        let _ = with_activity(|env, activity| {
            env.call_method(activity, "openAutofillSettings", "()V", &[])
                .map(|_| ())
        });
    }

    fn installs_updates(&self) -> bool {
        true
    }

    fn install_update(&self, package: &[u8]) -> Result<(), String> {
        with_activity(|env, activity| {
            let package = env.byte_array_from_slice(package)?;
            env.call_method(
                activity,
                "installUpdate",
                "([B)V",
                &[JValue::Object(&package)],
            )
            .map(|_| ())
        })
    }

    fn app_version(&self) -> Option<String> {
        self.text("appVersion")
    }

    fn language(&self) -> Option<String> {
        self.text("language")
    }

    fn scans_codes(&self) -> bool {
        true
    }

    fn open_link(&self, url: &str) {
        let _ = with_activity(|env, activity| {
            let url = env.new_string(url)?;
            env.call_method(
                activity,
                "openLink",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&url)],
            )
            .map(|_| ())
        });
    }

    fn renders_pdf(&self) -> bool {
        true
    }

    /// At most this many pages, each drawn this many pixels wide.
    fn render_pdf(&self, pdf: &[u8]) -> Result<Vec<(u32, u32, Vec<u8>)>, String> {
        const MAX_PAGES: i32 = 40;
        const WIDTH: i32 = 1080;
        let pages = with_activity(|env, activity| {
            let data = env.byte_array_from_slice(pdf)?;
            let count = env
                .call_method(activity, "pdfOpen", "([B)I", &[JValue::Object(&data)])?
                .i()?;
            let mut pages = Vec::new();
            for index in 0..count.min(MAX_PAGES) {
                let page = env
                    .call_method(
                        activity,
                        "pdfPage",
                        "(II)[B",
                        &[JValue::Int(index), JValue::Int(WIDTH)],
                    )?
                    .l()?;
                if page.is_null() {
                    break;
                }
                let pixels = env.convert_byte_array(JByteArray::from(page))?;
                let width = u32::try_from(WIDTH).unwrap_or(1);
                let height = u32::try_from(pixels.len() / (WIDTH as usize * 4)).unwrap_or(0);
                pages.push((width, height, pixels));
            }
            env.call_method(activity, "pdfClose", "()V", &[])?;
            Ok((count, pages))
        })?;
        match pages {
            (count, _) if count < 0 => Err("the PDF can't be read".into()),
            (_, pages) => Ok(pages),
        }
    }

    fn scan_code(&self, purpose: i32) -> Result<(), String> {
        crate::scan::scan(purpose)
    }
}

/// `VaultActivity.bioDone`: what a fingerprint prompt sealed (1) or opened (2), or why not.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_VaultActivity_bioDone<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    purpose: jint,
    data: JByteArray<'local>,
    error: JString<'local>,
) {
    let data = bytes(&mut env, &data).map(Zeroizing::new);
    let error = string(&mut env, &error).unwrap_or_default();
    on_ui(move |controller| {
        let answer = data.ok_or(error);
        match purpose {
            1 => controller.biometric_sealed(answer.map(|d| d.to_vec())),
            2 => controller.biometric_opened(answer),
            _ => {}
        }
    });
}

/// `VaultActivity.appLeft`: the app left the screen.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_VaultActivity_appLeft<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    on_ui(|controller| controller.left_app());
}

/// `VaultActivity.appBack`: the app is on screen again.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_VaultActivity_appBack<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    from_own_screen: jboolean,
) {
    let ask = from_own_screen == 0;
    on_ui(move |controller| controller.came_back(ask));
}

/// `VaultActivity.installStatus`: Android asks the person (""), or the update can't go in.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_VaultActivity_installStatus<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    error: JString<'local>,
) {
    let error = string(&mut env, &error).unwrap_or_default();
    on_ui(move |controller| controller.update_installing(&error));
}
