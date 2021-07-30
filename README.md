# zacket

Packet parsing in Zig inspired by [gopacket](https://github.com/google/gopacket)!

## Design

Every layer accepts a buffer rather than a reader as knowing the length of all the data is required to properly handle errors and decode Jumbo packets.
