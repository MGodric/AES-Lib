cmake_minimum_required(VERSION 3.25)
project(AES_Lib C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(aeslib STATIC aes.c)
target_include_directories(aeslib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(aes_demo examples/basic_demo.c)
target_link_libraries(aes_demo PRIVATE aeslib)

add_executable(core_vectors_test tests/core_vectors_test.c)
target_link_libraries(core_vectors_test PRIVATE aeslib)

add_executable(opmode_buffer_test tests/opmode_buffer_test.c)
target_link_libraries(opmode_buffer_test PRIVATE aeslib)

add_executable(opmode_kat_test tests/opmode_kat_test.c)
target_link_libraries(opmode_kat_test PRIVATE aeslib)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME core_vectors_test COMMAND core_vectors_test)
    add_test(NAME opmode_buffer_test COMMAND opmode_buffer_test)
    add_test(NAME opmode_kat_test COMMAND opmode_kat_test)
endif()
