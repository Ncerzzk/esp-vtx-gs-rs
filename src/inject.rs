use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    slice,
};

use zfec_rs::Fec;

use crate::{packet_h_bind::Ground2Air_Config_Packet, VtxPacketHeader, VTX_PACKET_HEADER_SIZE};

/*
   To prevent misunderstanding, "send data to air frame" would be named as inject here.
*/
pub struct InjectHandler {
    pub fec_k: u32,
    pub fec_n: u32,
    fec: Fec,
    cur_block_index: u32,
    packet_cnt: u32,
    raw_data: Vec<u8>,
}

type VtxPacketHeaderRaw = Vec<u8>;
type VtxPacketRaw = Vec<u8>;

#[derive(Default)]
#[repr(C, packed)]
struct RadiotapHeader {
    version: u8,
    pad: u8,
    it_len: u16,
    it_present: u32,
}

const WLAN_IEEE_HEADER_GROUND2AIR: [u8; 24] = [
    0x08, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x10, 0x86,
];

unsafe fn to_u8_slice<T>(origin: &T) -> &[u8] {
    let ptr = origin as *const T as *const u8;
    slice::from_raw_parts(ptr, std::mem::size_of::<T>())
}

impl InjectHandler {
    pub fn new(fec_k: u32, fec_n: u32) -> Self {
        InjectHandler {
            fec_k,
            fec_n,
            fec: Fec::new(fec_k as usize, fec_n as usize).unwrap(),
            cur_block_index: 0,
            packet_cnt: 0,
            raw_data: Vec::new(),
        }
    }

    fn new_raw_vtx_packet_header(
        block_index: u32,
        packet_index: u32,
        size: u16,
    ) -> VtxPacketHeaderRaw {
        let mut header = VtxPacketHeader(vec![0 as u8; VTX_PACKET_HEADER_SIZE]);
        header.set_block_index(block_index);
        header.set_packet_index(packet_index);
        header.set_size(size);
        header.0
    }

    fn new_raw_radiotap() -> Vec<u8> {
        let mut ret = Vec::new();
        let mut header = RadiotapHeader::default();
        header.it_present = (1 << 15) | (1 << 17); //  IEEE80211_RADIOTAP_DATA_RETRIES and IEEE80211_RADIOTAP_TX_FLAGS
        header.it_len = (std::mem::size_of::<RadiotapHeader>() + 3) as u16; // cal the len here, after we add header into vec, we could not edit it easily

        ret.extend_from_slice(unsafe { to_u8_slice(&header) });
        let f_t_no_ack = 0x08 as u16;
        ret.extend_from_slice(unsafe { to_u8_slice(&f_t_no_ack) }); // IEEE80211_RADIOTAP_TX_FLAGS
        ret.push(0x0); //  IEEE80211_RADIOTAP_DATA_RETRIES

        ret
    }

    fn new_inject_packet() -> VtxPacketRaw {
        let mut ret = Vec::new();
        ret.append(&mut Self::new_raw_radiotap());
        ret.extend_from_slice(&WLAN_IEEE_HEADER_GROUND2AIR);

        ret
    }

    pub fn push_ground2air_config_packet(
        &mut self,
        packet: &Ground2Air_Config_Packet,
    ) -> Vec<VtxPacketRaw> {
        let mut data = unsafe {
            let ptr = packet as *const Ground2Air_Config_Packet as *const u8;
            slice::from_raw_parts(ptr, std::mem::size_of::<Ground2Air_Config_Packet>()).to_vec()
        };
        data.resize(64, 0);
        self.push_data(&data)
    }
    pub fn push_data(&mut self, data: &[u8]) -> Vec<VtxPacketRaw> {
        assert_eq!(
            self.packet_cnt * data.len() as u32,
            self.raw_data.len() as u32
        ); // to make sure all the packet size is the same
        self.raw_data.extend_from_slice(data);

        if self.packet_cnt == self.fec_k - 1 {
            // we can start doing fec encode when recv fec_k packets
            // handle packet id [fec_k - 1 , fec_n)
            // we will get fec packets + 1 normal packet
            let fec_ret = self.fec.encode(&self.raw_data).unwrap();
            let mut ret: Vec<VtxPacketRaw> = Vec::new();
            for mut chunk in fec_ret.0 {
                if chunk.index < self.fec_k as usize - 1 {
                    continue;
                }
                let mut packet = Self::new_inject_packet();
                let mut header = Self::new_raw_vtx_packet_header(
                    self.cur_block_index,
                    chunk.index as u32,
                    chunk.data.len() as u16,
                );

                packet.append(&mut header);
                packet.append(&mut chunk.data);
                ret.push(packet);
            }
            self.cur_block_index += 1;
            self.packet_cnt = 0;
            self.raw_data.clear();
            return ret;
        } else {
            // we cannot do fec encode now
            // while we can directly return the packet out and inject it
            // just need to make sure the packet afterwards will be the same size.
            let mut packet: VtxPacketRaw = Self::new_inject_packet();
            let mut header = Self::new_raw_vtx_packet_header(
                self.cur_block_index,
                self.packet_cnt,
                (data.len() + VTX_PACKET_HEADER_SIZE) as u16,
            );
            packet.append(&mut header);
            packet.extend_from_slice(data);
            self.packet_cnt += 1;
            vec![packet]
        }
    }
}

#[cfg(test)]
mod tests {
    mod unittest {
        use zfec_rs::Fec;

        #[test]
        fn test_fec_encode() {
            let a = [
                1, 41, 0, 0, 0, 182, 0, 20, 12, 2, 3, 190, 5, 0, 0, 0, 8, 0, 0, 0, 255, 0, 0, 1, 1,
                0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 41, 0, 0, 0, 182, 0, 20, 12, 2, 3, 190, 5, 0,
                0, 0, 8, 0, 0, 0, 255, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];

            let fec = Fec::new(2, 6).unwrap();
            let (mut chunks, pad) = fec.encode(&a).unwrap();
            chunks.remove(2);
            chunks.remove(4);

            let decode = fec.decode(&chunks, pad).unwrap();
            for i in 0..decode.len() {
                assert_eq!(a[i], decode[i]);
            }
        }
    }
}
