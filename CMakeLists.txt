cmake_minimum_required(VERSION 3.10)
project(malware_gui)

set(CMAKE_CXX_STANDARD 17)

include_directories(
    imgui
    imgui/backends
    /usr/include/SDL2
)

file(GLOB IMGUI_SOURCES
    imgui/*.cpp
    imgui/backends/imgui_impl_sdl2.cpp
    imgui/backends/imgui_impl_opengl3.cpp
)

add_executable(malware_gui
    main.cpp
    ${IMGUI_SOURCES}
)

find_package(OpenGL REQUIRED)

# Link required libraries
target_link_libraries(malware_gui SDL2 GL dl pthread)