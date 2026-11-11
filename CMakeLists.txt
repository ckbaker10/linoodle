cmake_minimum_required(VERSION 3.12)
project(linoodle)
enable_language(ASM)
find_package(Threads REQUIRED)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build PE parser library
option(BUILD_SHARED_LIBS "" OFF)
add_subdirectory(pe-parse)
# pe-parse 76e3d41 builds with -Werror; GCC 13 reports dangling-pointer and
# sign-conversion warnings in it. Keep the warnings but do not fail the build.
target_compile_options(pe-parse PRIVATE -Wno-error)
set(BUILD_SHARED_LIBS ON)

# Build linoodle
add_library(linoodle linoodle.cpp windows_api.cpp windows_library.cpp)
target_link_libraries(linoodle PRIVATE pe-parse Threads::Threads)

# Build tester
add_executable(testlinoodle test/test.cpp)
target_link_libraries(testlinoodle PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
