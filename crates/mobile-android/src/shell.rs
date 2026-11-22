//! The system's file picker and "save as", through the app's activity
//! (`java/org/passwordvault/phone/VaultActivity.java`, a NativeActivity with these few
//! additions). The activity reads and writes the files; answers come back here on its threads
//! and go on to the controller on the UI thread.

use std::{cell::RefCell, rc::Weak};

use jni::{
    JNIEnv, JavaVM,
    objects::{JByteArray, JClass, JObject, JString, JValue},
};
use vault_mobile::Controller;

thread_local! {
    /// The controller, on the UI thread, for the picker's answers.
    pub(crate) static CONTROLLER: RefCell<Weak<Controller>> = const { RefCell::new(Weak::new()) };
}

/// Runs `f` with this thread's JNI environment and the activity.
#[allow(unsafe_code)]
fn with_activity<T>(
    f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>,
) -> Result<T, String> {
    let context = ndk_context::android_context();
    // SAFETY: the pointer is the process's JavaVM, registered by the activity glue (Slint's
    // Android backend) before any app code runs, and valid for the life of the process.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) }.map_err(|e| e.to_string())?;
    let mut env = vm.attach_current_thread().map_err(|e| e.to_string())?;
    // SAFETY: a global reference to the activity, kept by the glue for the life of the
    // process; wrapping it doesn't take ownership (a `JObject` deletes nothing on drop).
    let activity = unsafe { JObject::from_raw(context.context().cast()) };
    env.with_local_frame(8, |env| f(env, &activity))
        .map_err(|e| e.to_string())
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
fn on_ui(f: impl FnOnce(&Controller) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(controller) = CONTROLLER.with(|current| current.borrow().upgrade()) {
            f(&controller);
        }
    });
}

fn string(env: &mut JNIEnv, value: &JString) -> Option<String> {
    if value.is_null() {
        return None;
    }
    env.get_string(value).ok().map(Into::into)
}

fn bytes(env: &mut JNIEnv, value: &JByteArray) -> Option<Vec<u8>> {
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
    _name: JString<'local>,
    data: JByteArray<'local>,
    error: JString<'local>,
) {
    let data = bytes(&mut env, &data);
    let error = string(&mut env, &error);
    on_ui(move |controller| match (data, error) {
        (Some(bytes), _) => controller.bring_vault(bytes),
        (None, Some(error)) => controller.file_failed(&error),
        (None, None) => {}
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
        let place = name.unwrap_or_else(|| uri.clone());
        if !controller.copy_written(&place, read_back) {
            delete_document(&uri);
        }
    });
}
