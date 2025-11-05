cmake_minimum_required(VERSION 4.0)
project(sniffer C)

set(CMAKE_C_STANDARD 23)

find_package(Pcap REQUIRED)

add_executable(sniffer main.c)

target_link_libraries(sniffer PRIVATE
        Pcap::Pcap
        ws2_32
)