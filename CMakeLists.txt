cmake_minimum_required(VERSION 3.3)
project(SoFixer)

# =========================================================
# SoFixer options
# =========================================================
set(SO_64 OFF CACHE BOOL "build SoFixer for 64bit target")

if(SO_64)
    message("building SoFixer for 64bit target")
    add_definitions("-D__SO64__")
    set(TARGET_NAME SoFixer64)
else()
    message("building SoFixer for 32bit target")
    add_definitions("-D__SO32__")
    set(TARGET_NAME SoFixer32)
endif()



set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
if(MINGW)
    message("build with mingw")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++")
endif()

set(ROOT_SRC ElfReader.cpp
        ElfRebuilder.cpp
        ObElfReader.cpp)

add_executable(${TARGET_NAME} ${ROOT_SRC} main.cpp)
