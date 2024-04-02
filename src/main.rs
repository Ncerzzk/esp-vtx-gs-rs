use std::{
    collections::{HashMap, BTreeMap},
    fmt::Debug,
    mem::{size_of, MaybeUninit},
};

use bitfield::bitfield;
use esp_vtx_gs_rs::CapHandler;
use pcap::{Linktype, Packet};
use radiotap::Radiotap;
use zfec_rs::{Chunk, Fec};

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
