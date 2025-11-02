# MalSpector
A C++ GUI application for static and dynamic malware analysis on Linux, built with ImGui. This tool provides a framework for parsing executables and performing live debugging with `ptrace`.

## Features

**Static Analysis** (Powered by `file_parser.h`)
* **Multi-Format Support**: Parses both PE (Windows) and ELF (Linux) executable formats.
* **File Summary**: View file type, architecture, entry point, and file size.
* **Hashing**: Calculates MD5, SHA1, and SHA256 hashes for file identification.
* **Section Analysis**: Lists all file sections with virtual addresses, sizes, and entropy calculation (to detect packed/encrypted data).
* **Import Parsing**: Displays imported DLLs and functions for PE files.
* **String Extraction**: Dumps all printable strings from the binary (min. 5 characters).
* **Static Disassembly**: Uses Capstone to disassemble code at the file's entry point.

**Dynamic Analysis** (Powered by `ptrace` in `main.cpp`)
* **Live Debugger**: Start, pause, resume, and single-step processes under `ptrace`.
* **Syscall Log**: A live, color-coded log of system calls (like `openat`, `execve`, `socket`) made by the traced process.
* **Register Viewer**: Inspect all general-purpose CPU register values (RAX, RBX, RIP, RSP, etc.) when paused.
* **Memory Viewer**: Read and display the live memory of the debugged process in a hex-editor style view.
* **Breakpoint Management**: Set and remove `INT3` (0xCC) breakpoints at any memory address.
* **Live Disassembly**: Disassemble code live from the current instruction pointer (RIP) or any specified address.

**Visualization**
* **Behavior Graph**: Automatically generates a node-based graph (using ImNodes) to visualize process behavior.
* **Graph Features**: The graph plots relationships as they are discovered, linking processes to file access, network activity, and child process creation.

## Prerequisites

This project is intended for **Linux**. The following dependencies are required:
* `build-essential` (g++, make, etc.)
* `cmake` (3.10+)
* `pkg-config`
* `git`
* `libsdl2-dev` (for ImGui windowing)
* `libgtk-3-dev` (for Native File Dialog)
* `libcapstone-dev` (for disassembly)
* `libssl-dev` (for hashing)
* `libgl1-mesa-dev` (for OpenGL)

## Setup & Build

The provided `setup.sh` script automates the entire setup and build process.

1.  **Make the script executable:**
    ```bash
    chmod +x setup.sh
    ```

2.  **Run the script:**
    ```bash
    ./setup.sh
    ```
    This script will:
    * Install all system dependencies using `apt`.
    * Clone the required libraries (`imgui`, `imnodes`, `nativefiledialog`).
    * Compile the project into the `build/` directory.

3.  **Run the Application:**
    ```bash
    ./build/MalSpector
    ```

### Manual Build

If you prefer to build manually:

1.  **Install Dependencies:**
    ```bash
    sudo apt update
    sudo apt install -y build-essential cmake pkg-config git \
                       libsdl2-dev libgtk-3-dev libcapstone-dev \
                       libssl-dev libgl1-mesa-dev
    ```

2.  **Clone Libraries:**
    ```bash
    # ImGui (with docking)
    git clone [https://github.com/ocornut/imgui.git](https://github.com/ocornut/imgui.git)
    cd imgui && git checkout docking && cd ..
    mkdir -p imgui/backends
    cp imgui/backends/imgui_impl_sdl2.cpp imgui/backends/
    cp imgui/backends/imgui_impl_opengl3.cpp imgui/backends/
    cp imgui/backends/imgui_impl_sdl2.h imgui/backends/
    cp imgui/backends/imgui_impl_opengl3.h imgui/backends/

    # ImNodes
    git clone [https://github.com/Nelarius/imnodes.git](https://github.com/Nelarius/imnodes.git)

    # Native File Dialog
    git clone [https://github.com/mlabbe/nativefiledialog.git](https://github.com/mlabbe/nativefiledialog.git)
    ```

3.  **Compile:**
    ```bash
    mkdir build && cd build
    cmake ..
    make -j$(nproc)
    ```

## Usage

1.  Run the application:
    ```bash
    ./build/MalSpector
    ```
2.  Go to **File -> Open Static File** to load a PE or ELF binary.
3.  Use the **Static Analysis** menu to inspect file components (sections, strings, etc.).
4.  To begin dynamic analysis, select the loaded file in the "Loaded Files" window.
5.  In the "Debugger" window, click **Start Debug** to launch the process.

> **Warning**
> This is **NOT** a sandbox. The program being debugged runs live on your system with your user's permissions. Only analyze files you trust or in a dedicated, isolated virtual machine.

## License
This project is released for educational and research use only. Ensure your use complies with local and international laws.
