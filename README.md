# Low-Level Packet Sniffer (C++)

A raw packet capture tool written in C++ that interfaces directly with the Network Interface Controller (NIC) using `libpcap`. This tool captures live network traffic, parses the binary data manually, and extracts protocol headers.

## Features
- **Interface Selection:** Lists all available network adapters and allows user selection.
- **Promiscuous Mode:** Captures all traffic on the wire, not just traffic addressed to the host.
- **Protocol Parsing:**
  - **Ethernet:** Extracts MAC addresses and determines EtherType.
  - **IP (Layer 3):** Parses IPv4 headers, extracts Source/Dest IPs.
  - **TCP/UDP (Layer 4):** Parses ports and handles header length offsets.
  - **ICMP:** Identifies Ping requests and replies.
- **Payload Inspection:** Extracts and sanitizes ASCII data from the packet payload.
- **BPF Filtering:** Implements Berkeley Packet Filters (e.g., "tcp port 80").

## Technical Highlights
- **Pointer Arithmetic:** Manually navigating memory buffers to skip variable-length headers (IP/TCP options).
- **Memory Mapping:** Using C-style casting to map raw bytes onto system structs (`struct ip`, `struct tcphdr`).
- **Endianness Handling:** converting Network Byte Order (Big Endian) to Host Byte Order (Little Endian) using `ntohs`.

## Prerequisites
- **macOS/Linux:** `libpcap` installed (Native on macOS).
- **C++ Compiler:** Clang or GCC.
- **Build System:** CMake.

## Build and Run
```bash
mkdir build
cd build
cmake ..
make
sudo ./sniffer
```
**Must run with sudo/root priveleges**
