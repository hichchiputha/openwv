use std::ffi::{c_char, c_void};
use std::pin::Pin;

use crate::ffi::cdm;

/// Trait abstracting over different `Host_NN` interface versions. Note that we
/// only define the methods OpenWV actually uses, for brevity and better
/// compatibility across versions.
#[allow(non_snake_case)]
pub trait CommonHost {
    fn Allocate(self: Pin<&mut Self>, capacity: u32) -> *mut cdm::Buffer;
    fn OnInitialized(self: Pin<&mut Self>, success: bool);
    fn OnResolveKeyStatusPromise(self: Pin<&mut Self>, promise_id: u32, key_status: cdm::KeyStatus);
    unsafe fn OnResolveNewSessionPromise(
        self: Pin<&mut Self>,
        promise_id: u32,
        session_id: *const c_char,
        session_id_size: u32,
    );
    fn OnResolvePromise(self: Pin<&mut Self>, promise_id: u32);
    unsafe fn OnRejectPromise(
        self: Pin<&mut Self>,
        promise_id: u32,
        exception: cdm::Exception,
        system_code: u32,
        error_message: *const c_char,
        error_message_size: u32,
    );
    unsafe fn OnSessionMessage(
        self: Pin<&mut Self>,
        session_id: *const c_char,
        session_id_size: u32,
        message_type: cdm::MessageType,
        message: *const c_char,
        message_size: u32,
    );
    unsafe fn OnSessionKeysChange(
        self: Pin<&mut Self>,
        session_id: *const c_char,
        session_id_size: u32,
        has_additional_usable_key: bool,
        keys_info: *const cdm::KeyInformation,
        keys_info_count: u32,
    );
    unsafe fn OnSessionClosed(
        self: Pin<&mut Self>,
        session_id: *const c_char,
        session_id_size: u32,
    );
}

pub unsafe fn downcast_host<T: CommonHost + 'static>(
    ptr: *mut c_void,
) -> Option<&'static mut dyn CommonHost> {
    let typed_ptr: *mut T = ptr.cast();
    let concrete_ref = unsafe { typed_ptr.as_mut() };
    concrete_ref.map(|x| x as &mut dyn CommonHost)
}

macro_rules! impl_common_host {
    ($target:path) => {
        impl CommonHost for $target {
            fn Allocate(self: Pin<&mut Self>, capacity: u32) -> *mut cdm::Buffer {
                self.Allocate(capacity)
            }

            fn OnInitialized(self: Pin<&mut Self>, success: bool) {
                self.OnInitialized(success)
            }

            fn OnResolveKeyStatusPromise(
                self: Pin<&mut Self>,
                promise_id: u32,
                key_status: cdm::KeyStatus,
            ) {
                self.OnResolveKeyStatusPromise(promise_id, key_status)
            }

            unsafe fn OnResolveNewSessionPromise(
                self: Pin<&mut Self>,
                promise_id: u32,
                session_id: *const c_char,
                session_id_size: u32,
            ) {
                unsafe { self.OnResolveNewSessionPromise(promise_id, session_id, session_id_size) }
            }

            fn OnResolvePromise(self: Pin<&mut Self>, promise_id: u32) {
                self.OnResolvePromise(promise_id)
            }

            unsafe fn OnRejectPromise(
                self: Pin<&mut Self>,
                promise_id: u32,
                exception: cdm::Exception,
                system_code: u32,
                error_message: *const c_char,
                error_message_size: u32,
            ) {
                unsafe {
                    self.OnRejectPromise(
                        promise_id,
                        exception,
                        system_code,
                        error_message,
                        error_message_size,
                    )
                }
            }

            unsafe fn OnSessionMessage(
                self: Pin<&mut Self>,
                session_id: *const c_char,
                session_id_size: u32,
                message_type: cdm::MessageType,
                message: *const c_char,
                message_size: u32,
            ) {
                unsafe {
                    self.OnSessionMessage(
                        session_id,
                        session_id_size,
                        message_type,
                        message,
                        message_size,
                    )
                }
            }

            unsafe fn OnSessionKeysChange(
                self: Pin<&mut Self>,
                session_id: *const c_char,
                session_id_size: u32,
                has_additional_usable_key: bool,
                keys_info: *const cdm::KeyInformation,
                keys_info_count: u32,
            ) {
                unsafe {
                    self.OnSessionKeysChange(
                        session_id,
                        session_id_size,
                        has_additional_usable_key,
                        keys_info,
                        keys_info_count,
                    )
                }
            }

            unsafe fn OnSessionClosed(
                self: Pin<&mut Self>,
                session_id: *const c_char,
                session_id_size: u32,
            ) {
                unsafe { self.OnSessionClosed(session_id, session_id_size) }
            }
        }
    };
}

impl_common_host!(cdm::Host_10);
impl_common_host!(cdm::Host_11);
