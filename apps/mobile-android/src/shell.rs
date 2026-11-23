//! The system's file picker and "save as", through the app's activity
//! (`java/org/passwordvault/phone/VaultActivity.java`, a NativeActivity with these few
//! additions). The activity reads and writes the files; answers come back here on its threads
//! and go on to the controller on the UI thread.

use std::{
    cell::{Cell, RefCell},
    rc::Weak,
    sync::{Mutex, PoisonError},
};

use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue},
};
use vault_mobile::Controller;

thread_local! {
    /// The controller, on the UI thread, for the picker's answers.
    pub(crate) static CONTROLLER: RefCell<Weak<Controller>> = const { RefCell::new(Weak::new()) };
    /// What the open picker is for: 0 a vault file, else the screens' `pick-file` purpose.
    static PICKING: Cell<i32> = const { Cell::new(0) };
    /// What the open "save as" is for: false a copy of the vault, true an item's file.
    static SAVING_FILE: Cell<bool> = const { Cell::new(false) };
}

/// The picker, for a file with `purpose` (0 a vault file).
pub(crate) fn pick(purpose: i32) -> Result<(), String> {
    PICKING.with(|p| p.set(purpose));
    open_document()
}

/// "Save as" for an item's file (`true`) or a copy of the vault (`false`).
pub(crate) fn save(name: &str, data: &[u8], item_file: bool) -> Result<(), String> {
    SAVING_FILE.with(|s| s.set(item_file));
    create_document(name, data)
}

/// The activity (`VaultActivity`), as a global reference of this library's own. The context
/// `ndk_context` gives is the Application, which has none of the activity's methods.
static ACTIVITY: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// The process's JavaVM.
#[allow(unsafe_code)]
fn java_vm() -> Result<JavaVM, String> {
    let context = ndk_context::android_context();
    // SAFETY: the pointer is the process's JavaVM, registered by the activity glue (Slint's
    // Android backend) before any app code runs, and valid for the life of the process.
    unsafe { JavaVM::from_raw(context.vm().cast()) }.map_err(|e| e.to_string())
}

/// Keeps the activity of this run of `android_main` for [`with_activity`]. Called again on
/// every run, since Android may start the activity anew in the same process.
#[allow(unsafe_code)]
pub(crate) fn remember_activity(app: &slint::android::AndroidApp) -> Result<(), String> {
    let vm = java_vm()?;
    let env = vm.attach_current_thread().map_err(|e| e.to_string())?;
    // SAFETY: the glue's global reference to the activity, valid while `app` lives (it is
    // borrowed for this call); wrapping it doesn't take ownership (a `JObject` deletes
    // nothing on drop), and the reference kept is a new one of this library's own.
    let borrowed = unsafe { JObject::from_raw(app.activity_as_ptr().cast()) };
    let activity = env.new_global_ref(&borrowed).map_err(|e| e.to_string())?;
    *ACTIVITY.lock().unwrap_or_else(PoisonError::into_inner) = Some(activity);
    Ok(())
}

/// Runs `f` with this thread's JNI environment and the activity. A Java exception thrown on
/// the way is cleared and comes back as an error: one left pending makes the next JNI call
/// abort the whole app.
pub(crate) fn with_activity<T>(
    f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>,
) -> Result<T, String> {
    let activity = ACTIVITY
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .ok_or_else(|| "the activity isn't there yet".to_owned())?;
    let vm = java_vm()?;
    let mut env = vm.attach_current_thread().map_err(|e| e.to_string())?;
    let result = env.with_local_frame(8, |env| {
        let result = f(env, activity.as_obj());
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result
    });
    result.map_err(|e| e.to_string())
}

/// Shows the picker for a file to open; the file comes back to [`Controller::bring_vault`].
pub(crate) fn open_document() -> Result<(), String> {
    with_activity(|env, activity| {
        env.call_method(activity, "openDocument", "()V", &[])
            .map(|_| ())
    })
}

/// Shows the picker for where to save `data` as `name`; the activity writes it, reads it back
/// and hands that to [`Controller::copy_written`].
pub(crate) fn create_document(name: &str, data: &[u8]) -> Result<(), String> {
    with_activity(|env, activity| {
        let name = env.new_string(name)?;
        let data = env.byte_array_from_slice(data)?;
        env.call_method(
            activity,
            "createDocument",
            "(Ljava/lang/String;[B)V",
            &[JValue::Object(&name), JValue::Object(&data)],
        )
        .map(|_| ())
    })
}

/// Back at the first screen: the app goes to the background (it isn't closed).
pub(crate) fn leave() {
    let _ =
        with_activity(|env, activity| env.call_method(activity, "leave", "()V", &[]).map(|_| ()));
}

/// Deletes a document saved through the picker (a copy that failed its check).
fn delete_document(uri: &str) -> bool {
    with_activity(|env, activity| {
        let uri = env.new_string(uri)?;
        env.call_method(
            activity,
            "deleteDocument",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(&uri)],
        )?
        .z()
    })
    .unwrap_or(false)
}

/// Runs `f` with the controller on the UI thread.
pub(crate) fn on_ui(f: impl FnOnce(&Controller) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(controller) = CONTROLLER.with(|current| current.borrow().upgrade()) {
            f(&controller);
        }
    });
}

pub(crate) fn string(env: &mut JNIEnv, value: &JString) -> Option<String> {
    if value.is_null() {
        return None;
    }
    env.get_string(value).ok().map(Into::into)
}

pub(crate) fn bytes(env: &mut JNIEnv, value: &JByteArray) -> Option<Vec<u8>> {
    if value.is_null() {
        return None;
    }
    env.convert_byte_array(value).ok()
}

/// `VaultActivity.opened`: a file was chosen and read, or the picker was cancelled.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_VaultActivity_opened<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    name: JString<'local>,
    data: JByteArray<'local>,
    error: JString<'local>,
) {
    let name = string(&mut env, &name).unwrap_or_default();
    let data = bytes(&mut env, &data);
    let error = string(&mut env, &error);
    on_ui(move |controller| {
        let purpose = PICKING.with(|p| p.replace(0));
        match (data, error) {
            (Some(bytes), _) if purpose == 0 => controller.bring_vault(bytes),
            (Some(bytes), _) => controller.picked_file(purpose, &name, bytes),
            (None, Some(error)) => controller.file_failed(&error),
            (None, None) => {}
        }
    });
}

/// `VaultActivity.saved`: a copy was saved and read back, or not (or the picker was
/// cancelled). A copy that doesn't pass the controller's check is deleted.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_passwordvault_phone_VaultActivity_saved<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    uri: JString<'local>,
    name: JString<'local>,
    read_back: JByteArray<'local>,
    error: JString<'local>,
) {
    let uri = string(&mut env, &uri);
    let name = string(&mut env, &name);
    let read_back = bytes(&mut env, &read_back);
    let error = string(&mut env, &error);
    on_ui(move |controller| {
        let Some(uri) = uri else {
            return; // cancelled
        };
        let read_back = read_back.ok_or_else(|| error.unwrap_or_default());
        let kept = if SAVING_FILE.with(|s| s.replace(false)) {
            controller.file_written(read_back)
        } else {
            let place = name.unwrap_or_else(|| uri.clone());
            controller.copy_written(&place, read_back)
        };
        if !kept {
            delete_document(&uri);
        }
    });
}
