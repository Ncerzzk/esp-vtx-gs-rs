use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use esp_vtx_gs_rs::CapHandler;
use esp_vtx_gs_rs::tests::*;
fn main(){
    let mut time_sum:Duration = Duration::default();
    let mut time_sum_process_cap_packet = Duration::default();
    let mut time_sum_process_block_air2ground_packets = Duration::default();
    let mut time_sum_get_jpegout= Duration::default();
    let mut time_sum_udpsend= Duration::default();
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        
    let target_ip = Ipv4Addr::from_str("127.0.0.1").unwrap();
    let target = SocketAddr::new(target_ip.into(), 5000);
    
    for i in 0..1000 {
        let mut cap = pcap::Capture::from_file("./cap").unwrap();
        let mut cap_handler = CapHandler::new(FEC_K as u32, FEC_N as u32);
        let start_time = SystemTime::now();

        for _ in 0..10{
            let packet = cap.next_packet().unwrap();
            cap_handler.process_cap_packets(packet);
        }


        time_sum_process_cap_packet += start_time.elapsed().unwrap() / 10;

        let start_time = SystemTime::now();
        for blocks in cap_handler.blocks.keys().cloned().collect::<Vec<u32>>(){
            if let Some(ret) = cap_handler.process_block(blocks){
                cap_handler.process_air2ground_packets(ret);
            }
        }

        time_sum_process_block_air2ground_packets += start_time.elapsed().unwrap() / cap_handler.blocks.len() as u32;


        assert!(cap_handler.finish_frame_index != 0);
        let start_time = SystemTime::now();
        let data = cap_handler.frames.get(&cap_handler.finish_frame_index).unwrap().get_jpegdata();
        time_sum_get_jpegout += start_time.elapsed().unwrap();

        let start_time = SystemTime::now();
        socket.send_to(&data, target).unwrap();
        time_sum_udpsend += start_time.elapsed().unwrap();

    }

    let get_avg_time = |mut x:Duration,str:&str| {
        println!("{} escape avg:{} us",str,x.as_micros() as f32 / 1000.0); 
    };

    get_avg_time(time_sum_process_cap_packet,"process_cap_packet");
    get_avg_time(time_sum_process_block_air2ground_packets,"process block and air2ground packet");
    get_avg_time(time_sum_get_jpegout,"get jpeg");
    get_avg_time(time_sum_udpsend,"udp send");

}