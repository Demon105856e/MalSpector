cmake_minimum_required(VERSION 3.10)
project(malware_gui)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ImGui source files
set(IMGUI_DIR imgui)
set(IMGUI_BACKENDS_DIR ${IMGUI_DIR}/backends)

set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_BACKENDS_DIR}/imgui_impl_sdl2.cpp
    ${IMGUI_BACKENDS_DIR}/imgui_impl_opengl3.cpp
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
    pe_headers.cpp       # <-- ADDED
    ${IMGUI_SOURCES}
    ${NFD_SOURCES}
)

# Include directories
include_directories(
    ${IMGUI_DIR}
    ${IMGUI_BACKENDS_DIR}
    ${NFD_DIR}/include
)

# SDL2 and SDL2_image
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(SDL2_IMAGE REQUIRED SDL2_image)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

include_directories(
    ${SDL2_INCLUDE_DIRS}
    ${SDL2_IMAGE_INCLUDE_DIRS}
    ${GTK3_INCLUDE_DIRS}
)
link_directories(
    ${SDL2_LIBRARY_DIRS}
    ${SDL2_IMAGE_LIBRARY_DIRS}
    ${GTK3_LIBRARY_DIRS}
)

# OpenGL
find_package(OpenGL REQUIRED)

# Executable
add_executable(malware_gui ${SOURCES})

# Link libraries
target_link_libraries(malware_gui
    ${SDL2_LIBRARIES}
    ${SDL2_IMAGE_LIBRARIES}
    ${GTK3_LIBRARIES}
    OpenGL::GL
    GL
    dl
)
