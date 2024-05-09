use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    mem::{size_of, MaybeUninit},
    time::SystemTime,
};

use bitfield::bitfield;
use packet::Air2GroundFramePacket;
use packet_h_bind::WLAN_IEEE_HEADER_SIZE;
use pcap::{Packet};
use radiotap::Radiotap;
use zfec_rs::{Chunk, Fec};
pub mod device;

pub mod inject;
mod packet;
pub mod packet_h_bind;

pub const VTX_PACKET_HEADER_SIZE:usize = 6;
bitfield! {
    #[derive(Clone)]
    pub struct VtxPacketHeader([u8]);
    impl Debug;
    u32;
    pub block_index, set_block_index: 23, 0;
    pub packet_index, set_packet_index: 31, 24;
    u16;
    pub size,set_size: 47,32;
}

// const WLAN_IEEE_HEADER_LEN: usize = 24; // only when the cap linktype is IEEE802_11_RADIOTAP
// use WLAN_IEEE_HEADER_SIZE in packet_h_bind instead.

#[derive(Clone)]
pub struct VtxPacket {
    pub data: Vec<u8>,
    pub header: VtxPacketHeader<Vec<u8>>,
}

impl VtxPacket {
    fn from(payload: &[u8], fcs_enable: bool, fec_n: u32) -> Option<Self> {
        let header = VtxPacketHeader(payload[..VTX_PACKET_HEADER_SIZE].to_vec());

        if header.packet_index() >= fec_n {
            return None;
        }
        let size = if fcs_enable {
            payload.len() - 4
        } else {
            payload.len()
        } as usize;

        Some(VtxPacket {
            data: payload[VTX_PACKET_HEADER_SIZE..size].to_vec(),
            header,
        })
    }
}

#[derive(Clone)]
pub struct Block {
    pub packets: HashMap<u32, VtxPacket>,
    pub fec_packets: Vec<VtxPacket>,
    pub index: u32,
}

impl Block {
    fn new(index: u32) -> Self {
        Block {
            packets: HashMap::new(),
            fec_packets: Vec::new(),
            index,
        }
    }
}

pub struct Frame {
    parts: BTreeMap<u8, Air2GroundFramePacket>,
    frame_index: u32,
    parts_count: u8,
}

impl Frame {
    fn new(frame_index: u32) -> Self {
        Frame {
            parts: BTreeMap::new(),
            frame_index,
            parts_count: 0,
        }
    }

    pub fn get_jpegdata(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        for (_, air2ground_frame_packet) in &self.parts {
            ret.append(&mut air2ground_frame_packet.data.clone());
        }
        ret
    }
}
pub struct CapHandler {
    pub blocks: BTreeMap<u32, Block>,
    pub frames: BTreeMap<u32, Frame>,
    pub fec_k: u32,
    pub fec_n: u32,
    fec: Fec,
    pub finish_frame_index: u32,
    pub current_process_block_index: u32,
    callback: Option<Box<dyn FnMut(Frame)>>,
    pub stats:ConnectStats
}

pub struct ConnectStats {
    pub start_time: SystemTime,
    pub broken_block_count: u32,
}

impl ConnectStats {
    fn new() -> Self {
        ConnectStats {
            start_time: SystemTime::now(),
            broken_block_count: 0,
        }
    }
}

impl CapHandler {
    pub fn new(fec_k: u32, fec_n: u32) -> Self {
        CapHandler {
            blocks: BTreeMap::new(),
            frames: BTreeMap::new(),
            fec_k,
            fec_n,
            fec: Fec::new(fec_k as usize, fec_n as usize).unwrap(),
            finish_frame_index: 0,
            current_process_block_index: 0,
            callback: None,
            stats:ConnectStats::new(),
        }
    }

    pub fn do_when_recv_new_frame<F>(&mut self, func: F)
    where
        F: FnMut(Frame) + Send + 'static,
    {
        self.callback = Some(Box::new(func))
    }

    pub fn process_cap_packets(&mut self, packet: Packet) {
        let radiotap = Radiotap::from_bytes(&packet.data).unwrap();
        if radiotap.flags.unwrap().bad_fcs {
            panic!("bad fcs!");
        }
        let payload = &packet.data[radiotap.header.length + WLAN_IEEE_HEADER_SIZE..];
        /*
        let payload_valid_len = packet.header.len  // 1540
        - radiotap.header.length as u32 // 36
        - WLAN_IEEE_HEADER_LEN as u32 // 24
        - if radiotap.flags.unwrap().fcs { 4 } else { 0 };
        */

        let vtx_packet = VtxPacket::from(payload, radiotap.flags.unwrap().fcs, self.fec_n);
        if vtx_packet.is_none() {
            return;
        }
        let vtx_packet = vtx_packet.unwrap();

        if !self.blocks.contains_key(&vtx_packet.header.block_index()) {
            self.blocks.insert(
                vtx_packet.header.block_index(),
                Block::new(vtx_packet.header.block_index()),
            );
        }
        let block = self
            .blocks
            .get_mut(&vtx_packet.header.block_index())
            .unwrap();

        if vtx_packet.header.packet_index() >= self.fec_k {
            if !block
                .fec_packets
                .iter()
                .any(|x| x.header.packet_index() == vtx_packet.header.packet_index())
            {
                block.fec_packets.push(vtx_packet);
            }
        } else {
            if !block
                .packets
                .contains_key(&vtx_packet.header.packet_index())
            {
                block
                    .packets
                    .insert(vtx_packet.header.packet_index(), vtx_packet);
            }
        }
    }

    /*
       process the block by index.
       remove this block from blocks hashmap if it could be processed.
    */
    #[inline(always)]
    pub fn process_block(&mut self, block_index: u32) -> Option<Vec<u8>> {
        let block_ret = self.blocks.get_mut(&block_index);
        if block_ret.is_none() {
            return None;
        }

        let block = block_ret.unwrap();
        let out;
        if block.packets.len() == self.fec_k as usize {
            let mut entie_out = Vec::<u8>::with_capacity(1470 * self.fec_k as usize);
            for i in 0..self.fec_k {
                let mut packet = block.packets.remove(&i).unwrap();
                entie_out.append(&mut packet.data);
            }
            out = entie_out;
        } else if block.packets.len() + block.fec_packets.len() >= self.fec_k as usize {
            let mut chunks = Vec::<Chunk>::new();
            for i in 0..self.fec_k {
                let mut packet;
                if block.packets.contains_key(&i) {
                    packet = block.packets.remove(&i).unwrap();
                } else {
                    packet = block.fec_packets.pop().unwrap();
                }
                packet.data.resize(1470, 0);
                chunks.push(Chunk::new(
                    packet.data,
                    packet.header.packet_index() as usize,
                ));
                chunks.sort_by(|a, b| a.index.cmp(&b.index));
            }
            let fec_out = self.fec.decode(&chunks, 0).unwrap();
            out = fec_out;
        } else {
            return None;
        }
        self.current_process_block_index = block_index;
        self.blocks.remove(&block_index);

        Some(out)
    }

    pub fn process_block_with_fix_buffer(&mut self, block_index: u32) -> Option<Vec<u8>> {
        let ret = self.process_block(block_index);
        while let Some(x) = self.blocks.first_key_value(){
            if *x.0 <=  (if block_index >=2  { block_index - 2 }  else {0}) {
                self.blocks.pop_first().unwrap();
                // we are processing the "block_index" block
                // reserve a block as buffer
            }else{
                break
            }
        }
        ret
    }

    pub fn process_air2ground_packets(&mut self, data: Vec<u8>) {
        assert_eq!(data.len() % 1470, 0);
        let mut rest_data = data;
        while rest_data.len() >= 1470 {
            let tmp = rest_data.split_off(1470);
            let packet = Air2GroundFramePacket::from_bytes(rest_data);
            rest_data = tmp;

            let frame_index = packet.header.frame_index;
            if frame_index < self.finish_frame_index {
                // the air side may be restart, so clear blocks and restart
                self.blocks.clear();
                self.finish_frame_index = 0;
                return ;
            }

            if !self.frames.contains_key(&frame_index) {
                self.frames.insert(frame_index, Frame::new(frame_index));
            }

            let frame = self.frames.get_mut(&frame_index).unwrap();
            let real_part_index = packet.header.part_index();
            let last_part = packet.header.last_part();
            frame.parts.insert(real_part_index, packet);

            if last_part != 0 {
                frame.parts_count = real_part_index + 1; // update the parts_count when recv last part
            }
            if frame.parts_count != 0 && frame.parts.len() == frame.parts_count as usize {
                self.finish_frame_index = frame_index;
                if self.callback.is_some() {
                    (self.callback.as_mut().unwrap())(self.frames.remove(&self.finish_frame_index).unwrap());
                    self.frames.clear();
                }
                // if self.callback is None, then the frame will not be poped out
                // let's keep all the frame when no callback apply
            }
        }
    }
}

/*
    How the data construct:
    CapPacketHeader |  RadiotapHeader |  WLAN_IEEE_HEADER | VtxPacketHeader | Air2GroundPacketHeader | FramePayload
    A jpeg frame could be split to several air2ground packets.
*/

pub mod tests {
    use super::*;

    pub const FEC_K: usize = 2;
    pub const FEC_N: usize = 3;

    pub fn init_cap_and_recv_packets(num: usize) -> CapHandler {
        let mut cap = pcap::Capture::from_file("/home/ncer/esp-vtx-gs-rs/cap").unwrap();
        let mut cap_handler = CapHandler::new(FEC_K as u32, FEC_N as u32);
        for _ in 0..num {
            let packet = cap.next_packet().unwrap();
            cap_handler.process_cap_packets(packet);
        }
        cap_handler
    }

    pub fn find_block(
        cap_handler: &CapHandler,
        packet_len: Option<u32>,
        fec_packet_len: Option<u32>,
    ) -> Option<(u32, &Block)> {
        let ret = cap_handler.blocks.iter().find(|(_, block)| {
            // if no condition provided, return one block
            let mut ret = true;
            if let Some(p_len) = packet_len {
                ret &= block.packets.len() == p_len as usize;
            }
            if let Some(fec_len) = fec_packet_len {
                ret &= block.fec_packets.len() == fec_len as usize;
            }
            ret
        });
        if ret.is_none() {
            return None;
        } else {
            Some((ret.unwrap().0.clone(), ret.unwrap().1))
        }
    }

    #[cfg(test)]
    mod unittest {
        use std::sync::{Arc, RwLock};

        use super::*;
        #[test]
        fn test_process_air2ground_packet() {
            let mut cap_handler = init_cap_and_recv_packets(40);
            let mut keys: Vec<u32> = cap_handler.blocks.keys().cloned().collect();
            keys.sort();
            for block_index in keys {
                println!("{}", block_index);
                if let Some(out) = cap_handler.process_block(block_index) {
                    cap_handler.process_air2ground_packets(out);
                }
            }
            assert_ne!(cap_handler.finish_frame_index, 0);
        }

        #[test]
        fn test_call_back() {
            let mut cap_handler = init_cap_and_recv_packets(40);
            let test_cnt = Arc::new(RwLock::new(0));
            let test_cnt_copy = test_cnt.clone();
            cap_handler.do_when_recv_new_frame(move |_| {
                let mut copy = test_cnt_copy.write().unwrap();
                *copy += 1;
                println!("frame cnt:{}", *copy);
            });
            let keys: Vec<u32> = cap_handler.blocks.keys().cloned().collect();
            for idx in keys {
                if let Some(out) = cap_handler.process_block(idx) {
                    cap_handler.process_air2ground_packets(out);
                }
            }
            assert_ne!(cap_handler.frames.len(), *test_cnt.read().unwrap());
            assert!(*test_cnt.read().unwrap() != 0);
        }

        #[test]
        fn test_process_block_with_buffer() {
            let mut cap_hander = init_cap_and_recv_packets(40);
            let mut keys: Vec<u32> = cap_hander.blocks.keys().cloned().collect();
            keys.sort();
            keys.reverse();

            assert!(cap_hander.blocks.len() > 5);
            cap_hander.process_block_with_fix_buffer(keys[0]);
            assert!(cap_hander.blocks.len() == 2);
        }

        #[test]
        fn test_air2ground_packets_parse() {
            let cap_handler = init_cap_and_recv_packets(20);
            let (_, block) = cap_handler
                .blocks
                .iter()
                .find(|(_, x)| x.packets.len() == 2)
                .unwrap();

            let packet = block.packets.get(&0).unwrap().clone();
            let d = Air2GroundFramePacket::from_bytes(packet.data);
            println!("{:?}", d.header);
        }

        #[test]
        fn test_process_block() {
            let mut cap_handler = init_cap_and_recv_packets(20);
            let (idx, _) = find_block(&cap_handler, Some(2), None).unwrap();
            assert!(cap_handler.process_block(idx).is_some());

            let (idx, _) = find_block(&cap_handler, Some(1), Some(1)).unwrap();
            assert!(cap_handler.process_block(idx).is_some());
            assert!(!cap_handler.blocks.contains_key(&idx));

            let (idx, _) = find_block(&cap_handler, Some(1), Some(0)).unwrap();
            assert!(cap_handler.process_block(idx).is_none());
        }

        #[test]
        fn test_fec_decode() {
            let mut cap_handler = init_cap_and_recv_packets(20);

            let (target_idx, target_block) = cap_handler
                .blocks
                .iter()
                .find(|(_, block)| {
                    block.packets.len() == FEC_K as usize
                        && block.fec_packets.len() == (FEC_N - FEC_K) as usize
                })
                .unwrap();

            let mut block_copy = target_block.clone();
            let mut block_copy2 = target_block.clone();

            let origin_out = cap_handler.process_block(target_idx.clone()).unwrap();

            block_copy.packets.remove(&0).unwrap();
            block_copy2.packets.remove(&1).unwrap();

            cap_handler.blocks.insert(0, block_copy);
            cap_handler.blocks.insert(1, block_copy2);

            let new_out = cap_handler.process_block(0).unwrap();
            let new_out2 = cap_handler.process_block(1).unwrap();

            assert_eq!(origin_out.len(), new_out.len());
            assert_eq!(origin_out.len(), new_out2.len());
            println!("{:?}", &origin_out[..20]);
            println!("{:?}", &new_out[..20]);
            println!("{:?}", &origin_out[origin_out.len() - 20..]);
            println!("{:?}", &new_out[new_out.len() - 20..]);
            for i in 0..origin_out.len() {
                assert_eq!(origin_out[i], new_out[i]);
                assert_eq!(origin_out[i], new_out2[i]);
            }
        }
    }
}
