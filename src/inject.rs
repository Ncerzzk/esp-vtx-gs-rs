use std::{collections::{BTreeMap, VecDeque}, net::{UdpSocket, Ipv4Addr, SocketAddr}, slice};

use zfec_rs::Fec;

use crate::{Block, VtxPacket, VtxPacketHeader, VTX_PACKET_HEADER_SIZE, packet_h_bind::{Ground2Air_Config_Packet_Camera, Ground2Air_Config_Packet}};

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

    fn new_raw_vtx_packet_header(block_index: u32, packet_index: u32, size: u16) -> Vec<u8> {
        let mut header = VtxPacketHeader(vec![0 as u8; VTX_PACKET_HEADER_SIZE]);
        header.set_block_index(block_index);
        header.set_packet_index(packet_index);
        header.set_size(size);
        header.0
    }

    pub fn push_ground2air_config_packet(&mut self, packet:&Ground2Air_Config_Packet)  -> Vec<VtxPacketRaw> {
        let data = unsafe{
            let ptr = packet as *const Ground2Air_Config_Packet as *const u8;
            slice::from_raw_parts(ptr,std::mem::size_of::<Ground2Air_Config_Packet>())
        };
        self.push_data(data)
    }
    pub fn push_data(&mut self, data: &[u8]) -> Vec<VtxPacketRaw> {
        assert_eq!(self.packet_cnt * data.len() as u32, self.raw_data.len() as u32); // to make sure all the packet size is the same
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
                let mut packet = Vec::new();
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
            let mut packet: VtxPacketRaw = Vec::new();
            let mut header = Self::new_raw_vtx_packet_header(
                self.cur_block_index,
                self.packet_cnt,
                data.len() as u16,
            );
            packet.append(&mut header);
            packet.extend_from_slice(data);
            self.packet_cnt += 1;
            vec![packet]
        }
    }
}

fn control_thread(port:u16){
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let addr =SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(),port);
    socket.connect(addr).unwrap();

    let mut buf = [0 as u8; 1024];

    let inject_handler = InjectHandler::new(2,3);

    loop{
        //socket.recv(&mut buf).unwrap();
        let a = Ground2Air_Config_Packet::default();
        

    }
}
