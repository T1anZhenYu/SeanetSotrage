cmake_minimum_required (VERSION 3.8)

project ("Sagittarius")
set(CMAKE_CXX_COMPILER gcc)
#add_definitions(-std=c++17)

add_definitions(-Wall)
add_definitions(-Wextra)
#add_definitions(-Weffc++)
#add_definitions(-pedantic)
add_definitions(-Wsign-conversion)

add_definitions(-Wno-unused-function)
add_definitions(-Wno-unused-parameter)
add_definitions(-Wno-unused-variable)
add_definitions(-march=native)

message("CMAKE_C_FLAGS_DEBUG is ${CMAKE_C_FLAGS_DEBUG}")
message("CMAKE_C_FLAGS_RELEASE is ${CMAKE_C_FLAGS_RELEASE}")
message("CMAKE_C_FLAGS_RELWITHDEBINFO is ${CMAKE_C_FLAGS_RELWITHDEBINFO}")
message("CMAKE_C_FLAGS_MINSIZEREL is ${CMAKE_C_FLAGS_MINSIZEREL}")

#Set pkgconfig ENV
set(ENV{PKG_CONFIG_PATH} "/usr/local/lib64/pkgconfig")

# Porject-wide inlcude path
include_directories("include/common")
include_directories(SYSTEM "include/tldk")
include_directories("include/seadp_client")

# Porject-wide library path
link_directories("lib")

#Subdir for main app
add_subdirectory("bbr")
add_subdirectory("seadp_client")
add_subdirectory("main")