use std::{
    net::{UdpSocket, Ipv4Addr, SocketAddr}, sync::{Arc, RwLock}, time::SystemTime,
};

use clap::Parser;
use esp_vtx_gs_rs::CapHandler;
use pcap::{Linktype};
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

        let count: Arc<RwLock<u32>>  = Arc::new(RwLock::new(0));
        let count2 = count.clone();
        cap_hander.do_when_recv_new_frame(move |data|{
            socket.send_to(&data, target).unwrap();
            (*count2.write().unwrap()) += 1;
        });

        let mut last_time = std::time::SystemTime::now();
        loop{
            
            cap_hander.process_cap_packets(wlan_dev.cap.next_packet().unwrap());
            let block_indexs:Vec<u32> = cap_hander.blocks.keys().rev().cloned().collect();
            for block_idx in block_indexs{
                if let Some(complete_block) = cap_hander.process_block_with_fix_buffer(block_idx){
                    cap_hander.process_air2ground_packets(complete_block);
                }
            }

            if last_time.elapsed().unwrap().as_secs() >=1{
                println!("fps:{}",count.read().unwrap());
                *(count.write().unwrap()) = 0;
                last_time = SystemTime::now();
            }

        }
    }

}
