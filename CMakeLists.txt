cmake_minimum_required(VERSION 3.20)
project(ProcessGuard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Windows-only project
if(NOT WIN32)
    message(FATAL_ERROR "ProcessGuard is a Windows-only project.")
endif()

# Compiler flags
add_compile_options(
    /W4         # High warning level
    /WX         # Warnings as errors
    /permissive-
    /Zc:__cplusplus
)

# Common include directory
include_directories(${CMAKE_SOURCE_DIR}/common)

add_subdirectory(common)
add_subdirectory(target)
add_subdirectory(guardian)
add_subdirectory(attacker)
