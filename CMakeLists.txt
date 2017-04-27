cmake_minimum_required (VERSION 2.6)
project(sha512)

option(ONLY_LIB "Build the project as a library only" OFF)

include(TestBigEndian)
set(ByteOrder LITTLE_ENDIAN)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
  set(ByteOrder BIG_ENDIAN)
endif(IS_BIG_ENDIAN)

configure_file (
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h"
)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
add_library(sha512 SHA512.c SHA256.c)

if(NOT ONLY_LIB)
  add_executable(sha main.c)
  target_link_libraries(sha sha512)
endif(NOT ONLY_LIB)

