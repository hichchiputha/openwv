use autocxx::subclass::subclass;
use autocxx::include_cpp;

include_cpp! {
    #include "content_decryption_module.h"
    safety!(unsafe)
    subclass!("cdm::ContentDecryptionModule_11", OpenCdm)
}

#[subclass(self_owned)]
pub struct OpenCdm;

impl ffi::cdm::ContentDecryptionModule_11_methods for OpenCdm {
    fn Initialize(
        &mut self,
        allow_distinctive_identifier: bool,
        allow_persistent_state: bool,
        use_hw_secure_codecs: bool,
    ) {
        todo!()
    }

    fn GetStatusForPolicy(&mut self, promise_id: u32, policy: &ffi::cdm::Policy) {
        todo!()
    }

    unsafe fn SetServerCertificate(
        &mut self,
        promise_id: u32,
        server_certificate_data: *const u8,
        server_certificate_data_size: u32,
    ) {
        todo!()
    }

    unsafe fn CreateSessionAndGenerateRequest(
        &mut self,
        promise_id: u32,
        session_type: ffi::cdm::SessionType,
        init_data_type: ffi::cdm::InitDataType,
        init_data: *const u8,
        init_data_size: u32,
    ) {
        todo!()
    }

    unsafe fn LoadSession(
        &mut self,
        promise_id: u32,
        session_type: ffi::cdm::SessionType,
        session_id: *const ::std::os::raw::c_char,
        session_id_size: u32,
    ) {
        todo!()
    }

    unsafe fn UpdateSession(
        &mut self,
        promise_id: u32,
        session_id: *const ::std::os::raw::c_char,
        session_id_size: u32,
        response: *const u8,
        response_size: u32,
    ) {
        todo!()
    }

    unsafe fn CloseSession(
        &mut self,
        promise_id: u32,
        session_id: *const ::std::os::raw::c_char,
        session_id_size: u32,
    ) {
        todo!()
    }

    unsafe fn RemoveSession(
        &mut self,
        promise_id: u32,
        session_id: *const ::std::os::raw::c_char,
        session_id_size: u32,
    ) {
        todo!()
    }

    unsafe fn TimerExpired(&mut self, context: *mut autocxx::c_void) {
        todo!()
    }

    unsafe fn Decrypt(
        &mut self,
        encrypted_buffer: &ffi::cdm::InputBuffer_2,
        decrypted_buffer: *mut ffi::cdm::DecryptedBlock,
    ) -> ffi::cdm::Status {
        todo!()
    }

    fn InitializeAudioDecoder(
        &mut self,
        audio_decoder_config: &ffi::cdm::AudioDecoderConfig_2,
    ) -> ffi::cdm::Status {
        todo!()
    }

    fn InitializeVideoDecoder(
        &mut self,
        video_decoder_config: &ffi::cdm::VideoDecoderConfig_2,
    ) -> ffi::cdm::Status {
        todo!()
    }

    fn DeinitializeDecoder(&mut self, decoder_type: ffi::cdm::StreamType) {
        todo!()
    }

    fn ResetDecoder(&mut self, decoder_type: ffi::cdm::StreamType) {
        todo!()
    }

    unsafe fn DecryptAndDecodeFrame(
        &mut self,
        encrypted_buffer: &ffi::cdm::InputBuffer_2,
        video_frame: *mut ffi::cdm::VideoFrame,
    ) -> ffi::cdm::Status {
        todo!()
    }

    unsafe fn DecryptAndDecodeSamples(
        &mut self,
        encrypted_buffer: &ffi::cdm::InputBuffer_2,
        audio_frames: *mut ffi::cdm::AudioFrames,
    ) -> ffi::cdm::Status {
        todo!()
    }

    fn OnPlatformChallengeResponse(&mut self, response: &ffi::cdm::PlatformChallengeResponse) {
        todo!()
    }

    fn OnQueryOutputProtectionStatus(
        &mut self,
        result: ffi::cdm::QueryResult,
        link_mask: u32,
        output_protection_mask: u32,
    ) {
        todo!()
    }

    unsafe fn OnStorageId(&mut self, version: u32, storage_id: *const u8, storage_id_size: u32) {
        todo!()
    }

    fn Destroy(&mut self) {
        todo!()
    }
}
