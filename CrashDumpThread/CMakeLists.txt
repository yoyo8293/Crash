cmake_minimum_required(VERSION 3.15)
project(CrashDumpThread LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin/$<CONFIG>)

add_executable(CrashDumpThread CrashDumpThread.cpp)

target_link_libraries(CrashDumpThread PRIVATE dbghelp)

target_compile_options(CrashDumpThread PRIVATE $<$<CONFIG:Release>:/Zi /Oy->)
target_link_options(CrashDumpThread PRIVATE $<$<CONFIG:Release>:/DEBUG>)