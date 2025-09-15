cmake_minimum_required(VERSION 3.16)
project(VeilPNG_CLI C)

set(CMAKE_C_STANDARD 11)

option(BUILD_GUI "Build Windows GUI app" ON)

add_subdirectory(VeilPNG)
add_subdirectory(compat)

add_executable(veilpng_cli
  VeilPNG/cli_main.c
)

target_include_directories(veilpng_cli PRIVATE VeilPNG compat)

target_link_libraries(veilpng_cli PRIVATE veilpng_core compat_lib)

