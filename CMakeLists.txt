cmake_minimum_required(VERSION 3.2)
project(DDOSdetector)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(/usr/include)
link_directories(/usr/include)


set(SOURCE_FILES
    detectionapp.c
    detectionFunctions.h
    hashmap.c
    hashmap.h linkedList.c linkedList.h)

add_executable(DDOSdetector ${SOURCE_FILES})


target_link_libraries(DDOSdetector pcap)
target_link_libraries(DDOSdetector pthread)