cmake_minimum_required(VERSION 3.10)
project(cproxy C)

# Prevent in-tree builds to safeguard the custom Makefile
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "In-tree builds are not allowed. Please create a build directory (e.g. 'build') and run cmake from there, or use the provided Makefile.")
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Hardening & Security Compilation Flags (matching Makefile)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Werror -O2
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
    )
    add_link_options(
        -Wl,-z,relro,-z,now
        -pie
    )
endif()

# Source files
set(SOURCES
    src/main.c
    src/util.c
    src/cmd.c
    src/cgroup.c
    src/iptables.c
    src/args.c
    src/proc.c
)

# Header search paths
include_directories(include)

# Executable target
add_executable(cproxy ${SOURCES})

# Installation
install(TARGETS cproxy DESTINATION bin)
