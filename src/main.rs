use std::{
    collections::{HashMap, BTreeMap},
    fmt::Debug,
    mem::{size_of, MaybeUninit}, net::{UdpSocket, Ipv4Addr, SocketAddr},
};

use bitfield::bitfield;
use clap::Parser;
use esp_vtx_gs_rs::CapHandler;
use pcap::{Linktype, Packet};
use radiotap::Radiotap;
use zfec_rs::{Chunk, Fec};
use esp_vtx_gs_rs::device::Device;

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help(true))]
struct Cli{

    #[arg(short,long)]
    dev:Option<String>,

    #[arg(long, default_value_t=12345)]
    port:u32,

    #[arg(short,long)]
    test_file:Option<String>
}

/*
    How the data construct:
    CapPacketHeader |  RadiotapHeader |  WLAN_IEEE_HEADER | VtxPacketHeader | Air2GroundPacketHeader | FramePayload
    A jpeg frame could be split to several air2ground packets.
*/
fn main() {
    
    let args = Cli::parse();
    
    if let Some(test_file) = args.test_file{
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

    if let Some(dev) = args.dev{
        let mut wlan_dev = Device::new(dev);
        let mut cap_hander = CapHandler::new(2,3);
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let target =SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(),args.port as u16);
        loop{
            cap_hander.process_cap_packets(wlan_dev.cap.next_packet().unwrap());
            let (block_idx, _) = cap_hander.blocks.last_key_value().unwrap();
            if let Some(complete_block) = cap_hander.process_block_with_fix_buffer(*block_idx){
                cap_hander.process_air2ground_packets(complete_block);
            }
        }
    }

}
