cmake_minimum_required(VERSION 3.15)
project(CrashNullPtr LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin/$<CONFIG>)

add_executable(CrashNullPtr CrashNullPtr.cpp)

target_compile_options(CrashNullPtr PRIVATE $<$<CONFIG:Release>:/Zi /Oy->)
target_link_options(CrashNullPtr PRIVATE $<$<CONFIG:Release>:/DEBUG>)