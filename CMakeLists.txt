cmake_minimum_required(VERSION 3.15)
project(CrashAnalysisTools LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add all subprojects
add_subdirectory(CrashDump)
add_subdirectory(CrashDumpSymbol)
add_subdirectory(CrashDumpThread)
add_subdirectory(CrashMonitor)
