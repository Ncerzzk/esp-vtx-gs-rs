use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
    hash::Hash,
    mem::{size_of, MaybeUninit},
};

use bitfield::bitfield;
use pcap::{Linktype, Packet};
use radiotap::Radiotap;
use zfec_rs::{Chunk, Fec};

bitfield! {
    #[derive(Clone)]
    struct VtxPacketHeader([u8]);
    impl Debug;
    u32;
    block_index, _: 23, 0;
    packet_index, _: 31, 24;
    u16;
    size,_: 47,32;
}

enum Resolution {
    QVGA, //320x240
    CIF,  //400x296
    HVGA, //480x320
    VGA,  //640x480
    SVGA, //800x600
    XGA,  //1024x768
    SXGA, //1280x1024
    UXGA, //1600x1200
}

enum Air2GroundPacketType {
    Video,
    Telemetry,
}

#[repr(packed(1))]
struct Air2GroundFramePacketHeader {
    packet_type: Air2GroundPacketType,
    size: u32,
    pong: u8,
    crc: u8,
    resolution: Resolution,
    part_index: u8, // if msb is 1, then is the last part
    frame_index: u32,
}

impl Debug for Air2GroundFramePacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let packet_type = match self.packet_type {
            Air2GroundPacketType::Video => "Video",
            Air2GroundPacketType::Telemetry => "Telem",
        };
        let resolution = match self.resolution {
            Resolution::QVGA => "QVGA",
            Resolution::CIF => "CIF",
            Resolution::HVGA => "HVGA",
            Resolution::VGA => "VGA",
            Resolution::SVGA => "SVGA",
            Resolution::XGA => "XGA",
            Resolution::SXGA => "SXGA",
            Resolution::UXGA => "UXGA",
        };
        let size = self.size;
        let part_index = self.part_index;
        let frame_index = self.frame_index;
        f.debug_struct("Air2GroundFramePacketHeader")
            .field("packet_type", &packet_type)
            .field("size", &size)
            .field("pong", &self.pong)
            .field("crc", &self.crc)
            .field("resolution", &resolution)
            .field("part_index", &part_index)
            .field("frame_index", &frame_index)
            .finish()
    }
}

struct Air2GroundFramePacket {
    header: Air2GroundFramePacketHeader,
    data: Vec<u8>,
}

impl Air2GroundFramePacket {
    fn from_bytes(mut origin_data: Vec<u8>) -> Self {
        let payload = origin_data.split_off(size_of::<Air2GroundFramePacketHeader>());
        let mut header = MaybeUninit::<Air2GroundFramePacketHeader>::zeroed();
        unsafe {
            std::ptr::copy_nonoverlapping(
                origin_data.as_ptr() as *const Air2GroundFramePacketHeader,
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

const WLAN_IEEE_HEADER_LEN: usize = 24; // only when the cap linktype is IEEE802_11_RADIOTAP

#[derive(Clone)]
struct VtxPacket {
    data: Vec<u8>,
    header: VtxPacketHeader<Vec<u8>>,
    processed: bool, // show whether the packet has been processed or not
}

impl VtxPacket {
    fn from(payload: &[u8], fcs_enable: bool, fec_n: u32) -> Option<Self> {
        let header = VtxPacketHeader(payload[..6].to_vec());

        if header.packet_index() >= fec_n {
            return None;
        }
        let size = if fcs_enable {
            payload.len() - 4
        } else {
            payload.len()
        } as usize;

        Some(VtxPacket {
            data: payload[6..size].to_vec(),
            header,
            processed: false,
        })
    }
}

#[derive(Clone)]
struct Block {
    packets: HashMap<u32, VtxPacket>,
    fec_packets: Vec<VtxPacket>,
    index: u32,
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

struct Frame {
    parts: HashMap<u8, Air2GroundFramePacket>,
    frame_index: u32,
}
struct CapHandler {
    blocks: HashMap<u32, Block>,
    frames: HashMap<u32, Frame>,
    fec_k: u32,
    fec_n: u32,
    fec: Fec,
}

impl CapHandler {
    fn new(fec_k: u32, fec_n: u32) -> Self {
        CapHandler {
            blocks: HashMap::new(),
            frames: HashMap::new(),
            fec_k,
            fec_n,
            fec: Fec::new(fec_k as usize, fec_n as usize).unwrap(),
        }
    }

    fn process_cap_packets(&mut self, packet: Packet) {
        let radiotap = Radiotap::from_bytes(&packet.data).unwrap();
        if radiotap.flags.unwrap().bad_fcs {
            panic!("bad fcs!");
        }
        let payload = &packet.data[radiotap.header.length + WLAN_IEEE_HEADER_LEN..];
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
    fn process_block(&mut self, block_index: u32) -> Option<Vec<u8>> {
        let block = self.blocks.get_mut(&block_index).unwrap();

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
        self.blocks.remove(&block_index);
        Some(out)
    }

    fn process_air2ground_packets(&mut self,data:Vec<u8>){
        
    }
}

/*
    How the data construct:
    CapPacketHeader |  RadiotapHeader |  WLAN_IEEE_HEADER | VtxPacketHeader | Air2GroundPacketHeader | FramePayload
    A jpeg frame could be split to several air2ground packets.
*/
fn main() {
    let mut cap = pcap::Capture::from_file("/home/ncer/esp-vtx-gs-rs/cap").unwrap();
    let mut cap_handler = CapHandler::new(2, 3);
    assert_eq!(cap.get_datalink(), Linktype::IEEE802_11_RADIOTAP);
    for i in 0..10 {
        let packet = cap.next_packet().unwrap();
        cap_handler.process_cap_packets(packet);
    }

    for (idx, block) in cap_handler.blocks {
        println!("block:{} ", idx);
        for (p_idx, p) in block.packets {
            println!("packet:{} len:{}", p_idx, p.data.len());
        }
        for fec_packet in block.fec_packets {
            println!("fec packet:{}", fec_packet.header.packet_index());
        }
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use pcap::Capture;

    use super::*;

    const fec_k: usize = 2;
    const fec_n: usize = 3;

    fn init_cap_and_recv_packets(num: usize) -> CapHandler {
        let mut cap = pcap::Capture::from_file("/home/ncer/esp-vtx-gs-rs/cap").unwrap();
        let mut cap_handler = CapHandler::new(fec_k as u32, fec_n as u32);
        for _ in 0..num {
            let packet = cap.next_packet().unwrap();
            cap_handler.process_cap_packets(packet);
        }
        cap_handler
    }

    fn find_block(
        cap_handler: &CapHandler,
        packet_len: Option<u32>,
        fec_packet_len: Option<u32>,
    ) -> Option<(u32, &Block)> {
        let ret = cap_handler.blocks.iter().find(|(_, block)| {
            // if no condition provided, return one block
            let mut ret = true;
            if let Some(p_len) = packet_len{
                ret &= block.packets.len() == p_len as usize;
            }
            if let Some(fec_len) = fec_packet_len{
                ret &= block.fec_packets.len() == fec_len as usize;
            }
            ret
        });
        if ret.is_none(){
            return None;
        } else{
            Some((ret.unwrap().0.clone(), ret.unwrap().1))
        }
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
                block.packets.len() == fec_k as usize
                    && block.fec_packets.len() == (fec_n - fec_k) as usize
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
