use std::mem::MaybeUninit;

use crate::packet_h_bind::Air2Ground_Video_Packet;

pub struct Air2GroundFramePacket {
    pub header: Air2Ground_Video_Packet,
    pub data: Vec<u8>,
}

impl Air2GroundFramePacket {
    pub fn from_bytes(mut origin_data: Vec<u8>) -> Self {
        let payload = origin_data.split_off(std::mem::size_of::<Air2Ground_Video_Packet>());
        let mut header = MaybeUninit::<Air2Ground_Video_Packet>::zeroed();
        unsafe {
            std::ptr::copy_nonoverlapping(
                origin_data.as_ptr() as *const Air2Ground_Video_Packet,
                header.as_mut_ptr(),
                1,
            );
            Air2GroundFramePacket {
                header: header.assume_init(),
                data: payload,
            }
        }
    }
}