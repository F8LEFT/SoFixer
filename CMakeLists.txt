cmake_minimum_required(VERSION 3.3)
project(SoFixer)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if(S64)
    add_definitions(-DS64)
endif()

aux_source_directory(. ROOT_SRC)

if(SLibrary)
    add_library(SoFixer STATIC ${ROOT_SRC})
else()
    add_executable(SoFixer ${ROOT_SRC} main.cpp)
endif()

