
use esp_vtx_gs_rs::tests::{self, init_cap_and_recv_packets};
use std::net::{UdpSocket, SocketAddr, Ipv4Addr};
fn main(){
    let mut cap_handler = init_cap_and_recv_packets(40);
    let mut keys:Vec<u32> = cap_handler.blocks.keys().cloned().collect();
    keys.sort();
    for block_index in keys{
        if let Some(out) = cap_handler.process_block(block_index){
            cap_handler.process_air2ground_packets(out);
        }
    }
    assert_ne!(cap_handler.finish_frame_index , 0);
    
    let frame = cap_handler.frames.get(&cap_handler.finish_frame_index).unwrap();
    let data = frame.get_jpegdata();
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    
    let target =SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(),12345);
    loop {
        socket.send_to(&data,target).unwrap();
    }
    /*
    directly test the jpeg out:
    gst-launch-1.0 udpsrc port=12345 ! image/jpeg,width=200,height=200,framerate=30/1 ! jpegdec ! videoconvert ! autovideosink

    test adding rtp header to jpeg:
    server:
    gst-launch-1.0 udpsrc port=12345 ! image/jpeg,width=200,height=200,framerate=30/1 ! rtpjpegpay ! udpsink sync=false host=127.0.0.1 port=5600

    client(play):
    gst-launch-1.0 udpsrc port=5600  ! application/x-rtp, payload=26 ! rtpjpegdepay ! jpegdec ! videoconvert ! autovideosink
    or 
    ffplay rtp://127.0.0.1:5600
    
     */   
}
