use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
};

use bitfield::bitfield;
use pcap::{Linktype, Packet};
use radiotap::Radiotap;
use zfec_rs::{Chunk, Fec};

bitfield! {
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
struct Air2GroundPacketHeader {
    packet_type: Air2GroundPacketType,
    size: u32,
    pong: u8,
    crc: u8,
    resolution: Resolution,
    part_index: u8, // if msb is 1, then is the last part
    frame_index: u32,
}

const WLAN_IEEE_HEADER_LEN: usize = 24; // only when the cap linktype is IEEE802_11_RADIOTAP

struct VtxPacket {
    data: Vec<u8>,
    header: VtxPacketHeader<Vec<u8>>,
    processed: bool, // show whether the packet has been processed or not
}

impl VtxPacket {
    fn from(payload: &[u8], fcs_enable: bool) -> Option<Self> {
        let header = VtxPacketHeader(payload[..6].to_vec());
        let size = if fcs_enable {
            header.size() - 4
        } else {
            header.size()
        } as usize;
        if payload.len() < size + 6 {
            return None;
        }
        Some(VtxPacket {
            data: payload[6..size].to_vec(),
            header,
            processed: false,
        })
    }
}
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
struct CapHandler {
    blocks: HashMap<u32, Block>,
    frame_data: Vec<u8>,
    fec_k: u32,
    fec_n: u32,
    fec: Fec,
}

impl CapHandler {
    fn new(fec_k: u32, fec_n: u32) -> Self {
        CapHandler {
            blocks: HashMap::new(),
            frame_data: Vec::new(),
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

        let vtx_packet = VtxPacket::from(payload, radiotap.flags.unwrap().fcs);
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

    fn process_block(&mut self, block_index: u32)  -> Vec<u8>{
        let block = self.blocks.get_mut(&block_index).unwrap();

        let out;
        if block.packets.len() == self.fec_k as usize {
            let mut entie_out = Vec::<u8>::with_capacity(1470 * self.fec_k as usize);
            for i in 0..self.fec_k{
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
            }
            let fec_out = self.fec.decode(&chunks, 0).unwrap();
            out = fec_out;
        }else{
            out = Vec::new();
        }
        out
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
        for (p_idx, _) in block.packets {
            println!("packet:{}", p_idx);
        }
        for fec_packet in block.fec_packets {
            println!("fec packet:{}", fec_packet.header.packet_index());
        }
    }
}
