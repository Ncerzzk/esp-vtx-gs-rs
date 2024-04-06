use std::{mem::MaybeUninit, slice};

use crc::{Crc, CRC_8_SMBUS};

use crate::packet_h_bind::*;


pub struct Air2GroundFramePacket {
    pub header: Air2Ground_Video_Packet,
    pub data: Vec<u8>,
}

static SMBUS_CRC:Crc<u8> = Crc::<u8>::new(&CRC_8_SMBUS);

impl Air2Ground_Video_Packet{

    pub fn crc_check(&mut self) -> bool{
        let origin_crc = self._base.crc;
        self.crc_cal() == origin_crc
    }

    #[inline(always)]
    pub fn crc_cal(&mut self) -> u8{
        self._base.crc = 0;
        unsafe{
            let data = slice::from_raw_parts(self as *const Self as *const u8, std::mem::size_of::<Self>());
            self._base.crc =  SMBUS_CRC.checksum(data);
            self._base.crc
        } 
    }
}

impl Air2GroundFramePacket {
    pub fn from_bytes(mut origin_data: Vec<u8>) -> Self {
        let payload = origin_data.split_off(std::mem::size_of::<Air2Ground_Video_Packet>());
        let mut header = MaybeUninit::<Air2Ground_Video_Packet>::zeroed();
        let mut header_inited;
        unsafe {
            std::ptr::copy_nonoverlapping(
                origin_data.as_ptr() as *const Air2Ground_Video_Packet,
                header.as_mut_ptr(),
                1,
            );
            header_inited = header.assume_init();
        }

        if !header_inited.crc_check(){
            //panic!(" crc failed!");
            println!("[warning]crc check failed."); // just add a warning, as a crc failed frame is not a big issue on ground station.
        }

        Air2GroundFramePacket {
            header: header_inited,
            data: payload,
        }
    }
}

impl Default for Ground2Air_Config_Packet_Camera {
    fn default() -> Self {
        Self {
            resolution: Resolution_QVGA,
            fps_limit: 0,
            quality: 8,
            brightness: 0,
            contrast: 0,
            saturation: 0,
            sharpness: -1,
            denoise: 0,
            special_effect: 0,
            awb: true,
            awb_gain: true,
            wb_mode: 0,
            aec: true,
            aec2: true,
            ae_level: 0,
            aec_value: 0,
            agc: true,
            agc_gain: 0,
            gainceiling: 0,
            bpc: true,
            wpc: true,
            raw_gma: false,
            lenc: true,
            hmirror: false,
            vflip: false,
            dcw: true,
        }
    }
}

impl Default for Ground2Air_Header {
    fn default() -> Self {
        Self {
            type_: Ground2Air_Header_Type_Config,
            size: Default::default(),
            crc: Default::default(),
        }
    }
}

impl Ground2Air_Config_Packet{
    fn update_crc(&mut self){
        self._base.crc = 0;
        unsafe{
            let data = slice::from_raw_parts(self as *const Self as *const u8, std::mem::size_of::<Self>());
            self._base.crc =  SMBUS_CRC.checksum(data);
        } 
    }
}

impl Default for Ground2Air_Config_Packet {
    fn default() -> Self {
        let mut ret = Self {
            _base: Default::default(),
            ping: Default::default(),
            wifi_power: 20, 
            wifi_rate: WIFI_Rate_RATE_G_48M_ODFM,
            fec_codec_k: 2,
            fec_codec_n: 3,
            fec_codec_mtu: 1470,
            dvr_record: false,
            camera: Default::default(),
        };

        ret.update_crc();
        ret
    }
}
