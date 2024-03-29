use bitfield::bitfield;
use pcap::Linktype;
use radiotap::Radiotap;

bitfield! {
    struct VtxPacketHeader([u8]);
    impl Debug;
    u32;
    block_index, _: 23, 0;
    packet_index, _: 31, 24;
    u16;
    size,_: 47,32;
}

const WLAN_IEEE_HEADER_LEN: usize = 24;

fn main() {
    let mut cap = pcap::Capture::from_file("/home/ncer/esp-vtx-gs-rs/cap").unwrap();
    assert_eq!(cap.get_datalink(), Linktype::IEEE802_11_RADIOTAP);
    let packet = cap.next_packet().unwrap();

    let header = packet.header;

    let radiotap = Radiotap::from_bytes(&packet.data).unwrap();
    if radiotap.flags.unwrap().bad_fcs {
        panic!("bad fcs!");
    }

    let payload = &mut packet.data[radiotap.header.length + WLAN_IEEE_HEADER_LEN..];
    let payload_valid_len = packet.header.len
        - radiotap.header.length as u32
        - WLAN_IEEE_HEADER_LEN as u32
        - if radiotap.flags.unwrap().fcs { 4 } else { 0 };

    let vtx_packet_header = VtxPacketHeader(&payload[..6]);

    let mut fec_packets: Vec<Vec<u8>> = Vec::new();

    fec_packets.insert(vtx_packet_header.packet_index() as usize, unsafe {
        Vec::from_raw_parts(
            payload[6..].as_mut_ptr(),
            payload_valid_len as usize,
            payload_valid_len as usize,
        )
    });

    // the last 4 bytes are fcs

    println!("{:?}",);
    println!("Hello, world!");
}
