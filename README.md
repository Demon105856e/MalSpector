# AI-Powered Malware Analysis and Reverse Engineering GUI

This project is a Havoc C2-style GUI application for analyzing malware with features like:

* Graph view of malware behavior
* PE file inspector (headers, imports, strings, etc.)
* Debugger-style command console
* Decompiled code viewer

Built using ImGui with SDL2 and OpenGL.

---

## 🔧 Prerequisites (Kali Linux)

Before building the project, install the required development dependencies:

```bash
sudo apt update
sudo apt install -y build-essential cmake libsdl2-dev libgl1-mesa-dev libglew-dev libglfw3-dev
```

---

## 📁 Project Structure

```
malware_graph_gui/
├── imgui/                # Dear ImGui (with docking branch)
├── main.cpp              # Main application source
├── CMakeLists.txt        # CMake build configuration
└── README.md             # You're here :)
```

---

## 🚀 Setup Instructions

### 1. Clone ImGui with docking support

```bash
cd malware_graph_gui
git clone https://github.com/ocornut/imgui.git
cd imgui
git checkout docking
```

Also clone required backends:

```bash
cd ..
mkdir -p imgui/backends
cp -r imgui/examples/example_sdl_opengl3/imgui_impl_* imgui/backends/
```

> Ensure `imgui_impl_sdl2.cpp`, `imgui_impl_opengl3.cpp`, and their headers are in `imgui/backends/`

### 2. Build the Project

```bash
cd malware_graph_gui
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### 3. Run the GUI

```bash
./malware_gui
```

---

## 🧠 Notes

* If you face `DockBuilder` or `ImGui::` errors, make sure you're using **ImGui Docking** branch.
* The application requires OpenGL 3.0 support.
* Tested on: **Kali Linux (2024.x)** with **GCC 14+**

---

## ✅ TODO (Future Work)

* Load PE files dynamically
* Populate graph with behavioral data
* Integrate debugger and disassembler
* Add plugin architecture for extensibility

---

## 📜 License

This project is released for educational and research use only. Ensure your use complies with local and international laws.
