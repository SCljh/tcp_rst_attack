cmake_minimum_required(VERSION 3.15)
project(tcp_rst_attack)

set(CMAKE_CXX_STANDARD 14)

add_executable(tcp_rst_attack tcpcap.c)

TARGET_LINK_LIBRARIES(tcp_rst_attack pcap)
TARGET_LINK_LIBRARIES(tcp_rst_attack net)