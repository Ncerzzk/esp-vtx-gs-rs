use std::mem::MaybeUninit;

use pcap::{Activated, Active, Capture, Inactive};

pub struct Device {
    dev_name: String,
    pub cap: Capture<Active>,
}

impl Device {
    pub fn new(dev_name: String) -> Self {
        let mut cap: Option<Capture<Inactive>> = None;
        for i in pcap::Device::list().unwrap() {
            if i.name == dev_name {
                cap = Some(Capture::from_device(i).unwrap());
                break;
            }
        }

        if cap.is_none() {
            panic!(
                "could not find the device:{} or could not open it!",
                dev_name
            );
        }

        let cap = cap
            .unwrap()
            .snaplen(1800)
            .promisc(true)
            .rfmon(true)
            .timeout(-1)
            .immediate_mode(true)
            .buffer_size(16000000);
        
        let mut active_cap = cap.open().unwrap();

        active_cap.filter("ether[0x0a:4]==0x11223344 && ether[0x0e:2] == 0x5566", false).unwrap();

        Device {
            dev_name,
            cap: active_cap,
        }
    }

}
