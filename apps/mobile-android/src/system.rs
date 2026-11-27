//! What only Android does, for the controller (`vault_mobile::System`), through the activity
//! (`java/org/passwordvault/phone/VaultActivity.java` and `Biometrics.java`): fingerprint
//! unlock, the check before each use of a secret, keeping the app out of screenshots,
//! Android's autofill settings, installing an update. Answers that need the person come back to the native methods at the end of this
//! file, and go on to the controller on the UI thread.

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject, JString, JValue},
    sys::{jboolean, jint},
};
use vault_mobile::{
    PromptWords, System,
    system::{PageBudget, PdfPage, PdfPages},
};
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

    /// The phone's screen lock, asked of Android each time: when it can't tell, there is
    /// none (the app then asks what it can instead, or shows nothing).
    fn checks_person(&self) -> Option<bool> {
        Some(
            with_activity(|env, activity| {
                env.call_method(activity, "screenLockSet", "()Z", &[])?.z()
            })
            .unwrap_or(false),
        )
    }

    fn check_person(&self, words: &PromptWords) -> Result<(), String> {
        with_activity(|env, activity| {
            let title = env.new_string(&words.title)?;
            let detail = env.new_string(&words.detail)?;
            let cancel = env.new_string(&words.cancel)?;
            env.call_method(
                activity,
                "confirmPerson",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(&title),
                    JValue::Object(&detail),
                    JValue::Object(&cancel),
                ],
            )
            .map(|_| ())
        })
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

    fn utc_offset_minutes(&self) -> i32 {
        with_activity(|env, activity| {
            env.call_method(activity, "utcOffsetMinutes", "()I", &[])?
                .i()
        })
        .unwrap_or(0)
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

    fn render_pdf(&self, pdf: &[u8]) -> Result<PdfPages, String> {
        let drawn = with_activity(|env, activity| draw_pdf(env, activity, pdf));
        // Whatever happened on the way, the renderer is closed and the decrypted copy wiped.
        let closed = with_activity(|env, activity| {
            env.call_method(activity, "pdfClose", "()V", &[])
                .map(|_| ())
        });
        let drawn = drawn?.ok_or_else(|| "the PDF can't be read".to_owned())?;
        closed.map(|()| drawn)
    }

    fn scan_code(&self, purpose: i32) -> Result<(), String> {
        crate::scan::scan(purpose)
    }
}

/// The first pages of a PDF, each measured, held to the budget and only then drawn; `None` when
/// it can't be read.
fn draw_pdf(
    env: &mut JNIEnv,
    activity: &JObject,
    pdf: &[u8],
) -> jni::errors::Result<Option<PdfPages>> {
    let data = env.byte_array_from_slice(pdf)?;
    let total = env
        .call_method(activity, "pdfOpen", "([B)I", &[JValue::Object(&data)])?
        .i()?;
    env.delete_local_ref(data)?;
    let Ok(total) = u32::try_from(total) else {
        return Ok(None);
    };
    let mut budget = PageBudget::new(total);
    let mut pages = Vec::new();
    for index in 0..jint::try_from(budget.pages()).unwrap_or(0) {
        let index = JValue::Int(index);
        let size = env
            .call_method(activity, "pdfSize", "(I)J", &[index])?
            .j()?;
        // The width in the upper half, the height in the lower; -1 is a page with no size.
        let (wide, tall) = ((size >> 32) as i32, size as i32);
        let Some((width, height)) = budget.next_page(wide, tall) else {
            break;
        };
        let (wide, tall) = (
            jint::try_from(width).unwrap_or(0),
            jint::try_from(height).unwrap_or(0),
        );
        let page = env
            .call_method(
                activity,
                "pdfPage",
                "(III)[B",
                &[index, JValue::Int(wide), JValue::Int(tall)],
            )?
            .l()?;
        if page.is_null() {
            break;
        }
        let page = JByteArray::from(page);
        let pixels = env.convert_byte_array(&page)?;
        // Java's copy can go at once: held to the end, all the pages would be there twice.
        env.delete_local_ref(page)?;
        pages.push(PdfPage {
            width,
            height,
            pixels,
        });
    }
    Ok(Some(PdfPages { total, pages }))
}

/// `VaultActivity.bioDone`: what a fingerprint prompt sealed (1) or opened (2), that the
/// person passed the check before one use of a secret (3), or why not.
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
            3 => controller.person_checked(answer.map(|_| ())),
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
