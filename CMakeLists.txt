cmake_minimum_required(VERSION 3.15)
project(tcp_rst_attack)

set(CMAKE_CXX_STANDARD 14)
aux_source_directory(. DIR_SRCS)

add_executable(tcp_rst_attack main.c)
TARGET_LINK_LIBRARIES(tcp_rst_attack tools)
add_library(tools ${DIR_SRCS})

TARGET_LINK_LIBRARIES(tcp_rst_attack pcap)
TARGET_LINK_LIBRARIES(tcp_rst_attack net)