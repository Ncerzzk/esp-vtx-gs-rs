## ESP-VTX-GS

Ground Station of ESP-VTX. Rewrite from the c++ origin project: https://github.com/jeanlemotan/esp32-cam-fpv/tree/main/gs.

Why rewrite it? The main reason is that I don't like cpp, and I felt difficult and worried when I want to add some new features or do some refactoring,
so at last, I try using rust rewrite it. Not for performance or latency consideration, just for more easily maintain the project.

The new project will not inherit all features from origin project, actually I remove many of them (like GUI/JPEG decode etc. these may be added in the feture,
but for now, I prefer doing these work on Mobile platform.)

## Features
- receieve the jpeg parts packets and do FEC
- send data out through udp
- ground2air packets
- multi card support[ongoing]

### Send Data Through Udp
you can set the target ip by setting option argument:--target_ip

for example:
```
./esp-vtx-gs-rs -d DEVICE_NAME --target_ip 192.168.2.101
```

if you want to send jpeg data to mobile phone to work with:
https://github.com/Ncerzzk/ESPVTxAndroid

- connect mobile phone with the ground station board(PC or some other boards)
- mobile phone share internnet with ground station by usb
- check the mobile phone ip in ground station: `netstat -rn`
- set target_ip to the ip of mobile

## Development related
### bind generate
this project rely on some struct defined in c headers(packet.h and structures.h) as it's not a good way to redefine them in Rust.

so we use bindgen to generate the bind file:

```
bindgen packets.h -- -x c++ > bind_packet.rs
```

this file should be update and regenerated if c headers are edited in air sied.
