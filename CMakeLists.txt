cmake_minimum_required(VERSION 3.25)
project(AES_Lib C)

set(CMAKE_C_STANDARD 11)

add_executable(AES_Lib test.c aes.h aes.c opmode.c
        opmode.h)
