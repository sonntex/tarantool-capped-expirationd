cmake_minimum_required(VERSION 2.6)

project(capped-expirationd)

set(CMAKE_C_FLAGS "-std=c99 -Wall")
set(CMAKE_C_FLAGS_RELEASE "-g -O3")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

add_library(
  capped-expirationd SHARED
  expirationd.c)
target_link_libraries(
  capped-expirationd
  msgpuck)
