cmake_minimum_required(VERSION 3.10)
project(malware_gui)

if(POLICY CMP0072)
    cmake_policy(SET CMP0072 NEW)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ImGui source files
set(IMGUI_DIR imgui)
set(IMGUI_BACKENDS_DIR ${IMGUI_DIR}/backends)
set(IMNODES_DIR imnodes)

set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_BACKENDS_DIR}/imgui_impl_sdl2.cpp
    ${IMGUI_BACKENDS_DIR}/imgui_impl_opengl3.cpp
    ${IMNODES_DIR}/imnodes.cpp
)

# NFD for Linux (GTK)
set(NFD_DIR nativefiledialog/src)
set(NFD_SOURCES
    ${NFD_DIR}/nfd_common.c
    ${NFD_DIR}/nfd_gtk.c
)

# Source files
set(SOURCES
    main.cpp
    ${IMGUI_SOURCES}
    ${NFD_SOURCES}
)

# Include directories
include_directories(
    ${IMGUI_DIR}
    ${IMGUI_BACKENDS_DIR}
    ${NFD_DIR}/include
    ${IMNODES_DIR}
)

# Find all required libraries
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
pkg_check_modules(CAPSTONE REQUIRED capstone)
find_package(OpenGL REQUIRED)
find_package(OpenSSL REQUIRED) 
find_package(Threads REQUIRED)

include_directories(
    ${SDL2_INCLUDE_DIRS}
    ${GTK3_INCLUDE_DIRS}
    ${CAPSTONE_INCLUDE_DIRS}
    ${OpenSSL_INCLUDE_DIR} 
)

# Executable
add_executable(malware_gui ${SOURCES})

# Link libraries
target_link_libraries(malware_gui
    ${SDL2_LIBRARIES}
    ${GTK3_LIBRARIES}
    ${CAPSTONE_LIBRARIES}
    OpenSSL::SSL 
    OpenSSL::Crypto 
    Threads::Threads 
    OpenGL::GL
    dl
)