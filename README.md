## ESP-VTX-GS

Ground Station of ESP-VTX. Rewrite from the c++ origin project: https://github.com/jeanlemotan/esp32-cam-fpv/tree/main/gs.

Why rewrite it? The main reason is that I don't like cpp, and I felt difficult and worried when I want to add some new features or do some refactoring,
so at last, I try using rust rewrite it. Not for performance or latency consideration, just for more easily maintain the project.

The new project will not inherit all features from origin prject, actually I remove many of them (like GUI/JPEG decode etc. these may be added in the feture,
but for now, I prefer doing these work on Mobile platform.)

## Features
- receieve the jpeg parts packets and do FEC
- send data out through udp
- multi card support[ongoing]
- ground2air packets[ongoing]


## Development related
### bind generate
this project rely on some struct defined in c headers(packet.h and structures.h) as it's not a good way to redefine them in Rust.

so we use bindgen to generate the bind file:

```
bindgen packets.h -- -x c++ > bind_packet.rs
```

this file should be update and regenerated if c headers are edited in air sied.
