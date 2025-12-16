cmake_minimum_required(VERSION 3.10)
project(MacSniffer)

# 1. Create the executable from your source file
add_executable(sniffer main.cpp)

# 2. Link the executable to the system pcap library
# The linker on macOS knows where to find "pcap" automatically
target_link_libraries(sniffer pcap)