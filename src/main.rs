use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{Arc, RwLock, Condvar, Mutex},
    time::SystemTime, str::FromStr, collections::VecDeque,
};

use clap::Parser;
use esp_vtx_gs_rs::{device::Device, packet_h_bind::Ground2Air_Config_Packet, inject::InjectHandler, Frame};
use esp_vtx_gs_rs::CapHandler;
use pcap::Linktype;

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help(true))]
struct Cli {
    #[arg(short, long)]
    dev: Option<String>,

    // output port
    #[arg(long, default_value_t = 12345)]
    port: u32,

    // control port
    #[arg(long)]
    control_port: Option<u32>,

    // target ip
    #[arg(long,default_value = "127.0.0.1")]
    target_ip: String,

}

/*
    How the data construct:
    CapPacketHeader |  RadiotapHeader |  WLAN_IEEE_HEADER | VtxPacketHeader | Air2GroundPacketHeader | FramePayload
    A jpeg frame could be split to several air2ground packets.
*/

/*
   Do perf analyze:
   1. install cargo-flamegraph

   cargo install flamegraph

   2. release build and run:

   caro build --relase
   then execute it by sudo

   3. generate flamegraph:

   sudo sysctl -w kernel.perf_event_paranoid=-1
   sudo sysctl -p
   sudo flamegraph [-o my_flamegraph.svg] --pid XXX

   4. measure latency of gstreamer:

   env GST_DEBUG="GST_TRACER:7"     GST_TRACERS="latency(flags=element+pipeline)" GST_DEBUG_FILE=./latency.log \
   gst-launch-1.0 udpsrc port=12345 ! image/jpeg,width=200,height=200,framerate=30/1 ! rtpjpegpay mtu=1500 ! udpsink sync=false host=127.0.0.1 port=5600


*/
fn main() {
    let args = Cli::parse();

    if let Some(dev) = args.dev {
        let wlan_dev = Arc::new(RwLock::new(Device::new(dev)));
        let mut cap_hander = CapHandler::new(2, 3);
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        
        let target_ip = Ipv4Addr::from_str(&args.target_ip.as_str()).unwrap();
        let target = SocketAddr::new(target_ip.into(), args.port as u16);

        let count: Arc<RwLock<u32>> = Arc::new(RwLock::new(0));
        let count2 = count.clone();

        let send_frames :Arc<Mutex<VecDeque<Frame>>> = Arc::new(Mutex::new(VecDeque::new()));
        let send_frames_push = send_frames.clone();
        let cond= Arc::new(Condvar::new());
        let cond_push = cond.clone();
        
        cap_hander.do_when_recv_new_frame(move |frame| {
            let mut vec = send_frames_push.lock().unwrap();
            vec.push_back(frame);
            cond_push.notify_all();
            (*count2.write().unwrap()) += 1;
        });

        std::thread::spawn(move ||{
            loop{
                let mut vec = send_frames.lock().unwrap();
                if let Some(frame) = vec.pop_back(){
                    socket.send_to(&frame.get_jpegdata(),target).unwrap();
                }
                drop(cond.wait(vec));
            }
        });


        if args.control_port.is_some(){
            let wlan_dev_tx = wlan_dev.clone();
            std::thread::spawn(move ||{
                let config = Ground2Air_Config_Packet::default();
                let mut inject_handler = InjectHandler::new(2,6);
                loop{
                    let mut wlan_dev = wlan_dev_tx.write().unwrap();
                    let push_ret = inject_handler.push_ground2air_config_packet(&config);
                    for i in push_ret{
                        wlan_dev.cap.sendpacket(i).unwrap();
                    }
                    drop(wlan_dev);
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            });
        }


        let mut last_time = std::time::SystemTime::now();
        loop {
            let mut wlan_dev_unwrap = wlan_dev.write().unwrap();
            let packet = wlan_dev_unwrap.cap.next_packet().unwrap();   // TODO: change this block action to epoll 

            cap_hander.process_cap_packets(packet);
            drop(wlan_dev_unwrap);
            let block_indexs: Vec<u32> = cap_hander.blocks.keys().rev().cloned().collect();
            for block_idx in block_indexs {
                if let Some(complete_block) = cap_hander.process_block_with_fix_buffer(block_idx) {
                    cap_hander.process_air2ground_packets(complete_block);
                }
            }

            if last_time.elapsed().unwrap().as_secs() >= 1 {
                println!("fps:{}", count.read().unwrap());
                *(count.write().unwrap()) = 0;
                last_time = SystemTime::now();
            }
            
        }
    }
}
