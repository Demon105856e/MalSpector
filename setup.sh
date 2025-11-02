#!/bin/bash

# --- 1. Install System Dependencies ---
echo "📦 Installing system dependencies..."
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    git \
    libsdl2-dev \
    libgtk-3-dev \
    libcapstone-dev \
    libssl-dev \
    libgl1-mesa-dev

echo "✅ System dependencies installed."
echo "---------------------------------"


# --- 2. Clone Required Libraries ---
echo "📦 Cloning external libraries..."
# Create 'external' directory if it doesn't exist
# Clone ImGui (with docking branch)
if [ ! -d "imgui" ]; then
    git clone https://github.com/ocornut/imgui.git
    cd imgui
    git checkout docking
    cd ..
    echo "✅ Cloned ImGui (docking branch)."
else
    echo "ℹ️ 'imgui' directory already exists, skipping clone."
fi

# Setup ImGui backends
mkdir -p imgui/backends
cp imgui/backends/imgui_impl_sdl2.cpp imgui/backends/
cp imgui/backends/imgui_impl_opengl3.cpp imgui/backends/
cp imgui/backends/imgui_impl_sdl2.h imgui/backends/
cp imgui/backends/imgui_impl_opengl3.h imgui/backends/
echo "✅ Set up ImGui backends."

# Clone ImNodes
if [ ! -d "imnodes" ]; then
    git clone https://github.com/Nelarius/imnodes.git
    echo "✅ Cloned ImNodes."
else
    echo "ℹ️ 'imnodes' directory already exists, skipping clone."
fi

# Clone Native File Dialog
if [ ! -d "nativefiledialog" ]; then
    git clone https://github.com/mlabbe/nativefiledialog.git
    echo "✅ Cloned Native File Dialog."
else
    echo "ℹ️ 'nativefiledialog' directory already exists, skipping clone."
fi

# Go back to the project root
cd ..
echo "✅ All required libraries are in place."
echo "---------------------------------"


# --- 3. Build the Project ---
echo "🚀 Building MalSpector..."
# Create build directory
mkdir -p build
cd build

# Run CMake from within the build directory
cmake ..

# Compile the project
make -j$(nproc)

echo "---------------------------------"
echo "✅ Build complete!"
echo "You can now run the application with:"
echo "./build/MalSpector"
