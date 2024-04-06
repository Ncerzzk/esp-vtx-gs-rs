
use std::alloc::System;
use std::time::Duration;
use std::time::SystemTime;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use esp_vtx_gs_rs::CapHandler;
use esp_vtx_gs_rs::tests::*;

fn test_cap_handle(c: &mut Criterion){
    c.bench_function("test_schedule_bench_real", move |b| {
        b.iter_custom(|iters| {
            let mut time_sum:Duration = Duration::default();
            for i in 0..iters {
                let mut cap = pcap::Capture::from_file("./cap").unwrap();
                let mut cap_handler = CapHandler::new(FEC_K as u32, FEC_N as u32);
                let start_time = SystemTime::now();
                for cnt in 0..10{
                    let packet = cap.next_packet().unwrap();
                    cap_handler.process_cap_packets(packet);
                }
                for blocks in cap_handler.blocks.keys().cloned().collect::<Vec<u32>>(){
                    if let Some(ret) = cap_handler.process_block(blocks){
                        cap_handler.process_air2ground_packets(ret);
                    }
                }
                assert!(cap_handler.finish_frame_index != 0);
                cap_handler.frames.get(&cap_handler.finish_frame_index).unwrap().get_jpegdata();
                let escape = start_time.elapsed().unwrap();
                time_sum += escape;
            }
            time_sum
        })
    });
}
criterion_group!(benches, test_cap_handle);

criterion_main!(benches);