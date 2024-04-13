use std::time::SystemTime;

use clap::{Command, Parser};
use esp_vtx_gs_rs::device::Device;

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help(true))]
struct Cli {
    #[arg(short, long)]
    dev: String,
}

fn main(){
    let args = Cli::parse();
    let mut wlan_dev = Device::new(args.dev); 

    let start_time = SystemTime::now();
    let mut cnt = 0;
    while start_time.elapsed().unwrap().as_millis() <= 10* 1000{
        let packet = wlan_dev.cap.next_packet();
        cnt +=1;
    }

    println!("recv {} packets in 10s",cnt);
    println!("{:?}",wlan_dev.cap.stats());
}