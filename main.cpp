#include "imgui.h"
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"
#include "imgui_internal.h"
#include "imnodes.h"

#include <SDL.h>
#include <SDL_opengl.h>
#include <GL/gl.h>
#include <stdio.h>
#include <string>
#include <memory>
#include <vector>
#include <map>

#include "nativefiledialog/src/include/nfd.h"
#include "file_parser.h" 

// --- DYNAMIC ANALYSIS ---
#include <thread>
#include <mutex>
#include <atomic>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <chrono>
#include <capstone/capstone.h>

// --- GLOBAL STATE ---

// -- File Management --
struct FileAnalysisSession {
    std::string path;
    std::string filename;
    std::unique_ptr<FileParser> parser;
};
static std::vector<FileAnalysisSession> loaded_files;
static int active_file_index = -1; 

// -- Window Toggles --
static bool show_graph_view_window = true;
static bool show_debugger_window = true;
static bool show_loaded_files_window = true; 
static bool show_summary_window = false;
static bool show_sections_window = false;
static bool show_entropy_window = false;
static bool show_imports_window = false;
static bool show_strings_window = false;
static bool show_disassembly_window = false;
static bool show_registers_window = false;
static bool show_memory_window = false;
static bool show_breakpoints_window = false;

// --- Guard flag for UI initialization ---
static bool g_DockspaceInitialized = false;

// -- Dynamic Analysis & Graph State --
static std::vector<std::string> syscall_log;
static std::mutex log_mutex;
static std::atomic<bool> is_tracing = false;
static std::thread tracer_thread;
static std::string traced_process_name = "";
static std::map<pid_t, std::string> traced_processes; 

// --- Debugger Control State ---
static std::mutex debugger_mutex;
static bool should_step = false;
static bool is_paused = false;
static bool single_step_mode = false;
static pid_t current_debug_pid = -1;
static std::vector<pid_t> traced_pids;

FileParser* get_active_parser(); // Add this line


// --- Breakpoints ---
struct Breakpoint {
    uint64_t address;
    bool enabled;
    long original_data;
};
static std::map<uint64_t, Breakpoint> breakpoints;
static std::mutex breakpoints_mutex;

// --- Graph Structures ---
struct GraphNode {
    int id;
    std::string label;
};
struct GraphLink {
    int id;
    int start_node, end_node;
};

static std::vector<GraphNode> graph_nodes;
static std::vector<GraphLink> graph_links;
static std::map<std::string, int> node_name_to_id_map;
static int next_node_id = 0;
static int next_link_id = 0;
static size_t log_processed_index = 0;
static std::mutex graph_mutex;

// --- ImNodes interaction variables ---
static int link_start = -1;
static int link_end = -1;
static int hovered_node = -1;

// --- Syscall Map (x86_64) ---
static std::map<long, std::string> syscall_map = {
    {__NR_openat, "openat"}, {__NR_socket, "socket"}, {__NR_connect, "connect"},
    {__NR_execve, "execve"}, {__NR_read, "read"}, {__NR_write, "write"}, {__NR_close, "close"},
    {__NR_clone, "clone"}, {__NR_fork, "fork"}, {__NR_vfork, "vfork"}
};
std::string get_syscall_name(long code) {
    if (syscall_map.count(code)) { return syscall_map[code]; }
    return "UNKNOWN_SYSCALL (" + std::to_string(code) + ")";
}

// --- DEBUGGER FUNCTIONS ---
bool set_breakpoint(pid_t pid, uint64_t address) {
    std::lock_guard<std::mutex> lock(breakpoints_mutex);
    
    // Read original data
    long data = ptrace(PTRACE_PEEKDATA, pid, address, NULL);
    if (errno != 0) return false;
    
    // Insert breakpoint (INT3 instruction)
    long int3 = (data & ~0xFF) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, address, int3) == -1) return false;
    
    breakpoints[address] = {address, true, data};
    return true;
}

bool remove_breakpoint(pid_t pid, uint64_t address) {
    std::lock_guard<std::mutex> lock(breakpoints_mutex);
    
    if (breakpoints.find(address) == breakpoints.end()) return false;
    
    // Restore original data
    if (ptrace(PTRACE_POKEDATA, pid, address, breakpoints[address].original_data) == -1) return false;
    
    breakpoints.erase(address);
    return true;
}

void single_step(pid_t pid) {
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
}

void continue_execution(pid_t pid) {
    ptrace(PTRACE_CONT, pid, NULL, NULL);
}

struct user_regs_struct get_registers(pid_t pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    return regs;
}

std::string read_memory(pid_t pid, uint64_t address, size_t size) {
    std::string result;
    for (size_t i = 0; i < size; i += sizeof(long)) {
        long data = ptrace(PTRACE_PEEKDATA, pid, address + i, NULL);
        if (errno != 0) break;
        
        char* bytes = (char*)&data;
        for (int j = 0; j < sizeof(long) && (i + j) < size; j++) {
            result += bytes[j];
        }
    }
    return result;
}

std::vector<std::string> disassemble_at_address(pid_t pid, uint64_t address, size_t count = 10) {
    std::vector<std::string> instructions;
    
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        instructions.push_back("Failed to initialize Capstone");
        return instructions;
    }
    
    // Read memory for disassembly
    std::string code_bytes = read_memory(pid, address, 100);
    if (code_bytes.empty()) {
        instructions.push_back("Failed to read memory");
        cs_close(&handle);
        return instructions;
    }
    
    cs_insn *insn;
    size_t disasm_count = cs_disasm(handle, 
                                   (const uint8_t*)code_bytes.c_str(), 
                                   code_bytes.size(),
                                   address, count, &insn);
    
    if (disasm_count > 0) {
        for (size_t i = 0; i < disasm_count; i++) {
            char buffer[256];
            snprintf(buffer, sizeof(buffer), "0x%lx: %s %s", 
                    insn[i].address, insn[i].mnemonic, insn[i].op_str);
            instructions.push_back(buffer);
        }
        cs_free(insn, disasm_count);
    } else {
        instructions.push_back("Failed to disassemble");
    }
    
    cs_close(&handle);
    return instructions;
}

// --- PTRACE DYNAMIC ANALYSIS ---
std::string read_string_from_child(pid_t child, unsigned long addr) {
    std::string str;
    for (int i = 0; i < 128; ++i) {
        long data = ptrace(PTRACE_PEEKDATA, child, addr + i * sizeof(long), NULL);
        if (errno != 0) break;
        char* bytes = (char*)&data;
        for (int j = 0; j < sizeof(long); j++) {
            if (bytes[j] == '\0') return str;
            str += bytes[j];
        }
    }
    return str;
}

// --- DEBUGGER CONTROL FUNCTIONS ---
void pause_trace() {
    std::lock_guard<std::mutex> lock(debugger_mutex);
    if (is_tracing && !is_paused) {
        is_paused = true;
        if (current_debug_pid != -1) {
            kill(current_debug_pid, SIGSTOP);
        }
        std::lock_guard<std::mutex> log_lock(log_mutex);
        syscall_log.push_back("--- DEBUGGER PAUSED ---");
    }
}

void resume_trace() {
    std::lock_guard<std::mutex> lock(debugger_mutex);
    if (is_tracing && is_paused) {
        is_paused = false;
        if (current_debug_pid != -1) {
            continue_execution(current_debug_pid);
        }
        std::lock_guard<std::mutex> log_lock(log_mutex);
        syscall_log.push_back("--- DEBUGGER RESUMED ---");
    }
}

void step_trace() {
    std::lock_guard<std::mutex> lock(debugger_mutex);
    if (is_tracing && is_paused && current_debug_pid != -1) {
        should_step = true;
        single_step_mode = true;
        single_step(current_debug_pid);
    }
}

void set_single_step_mode(bool enable) {
    std::lock_guard<std::mutex> lock(debugger_mutex);
    if (is_tracing) {
        single_step_mode = enable;
        if (enable) {
            is_paused = true;
            std::lock_guard<std::mutex> log_lock(log_mutex);
            syscall_log.push_back("--- SINGLE STEP MODE ENABLED ---");
        } else {
            is_paused = false;
            if (current_debug_pid != -1) {
                continue_execution(current_debug_pid);
            }
            std::lock_guard<std::mutex> log_lock(log_mutex);
            syscall_log.push_back("--- SINGLE STEP MODE DISABLED ---");
        }
    }
}

// --- UPGRADED DEBUGGER FUNCTION ---
void debug_program(std::string path) {
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        syscall_log.clear();
        log_processed_index = 0; 
        syscall_log.push_back("Starting debug of: " + path);
    }
    {
        std::lock_guard<std::mutex> lock(graph_mutex); 
        graph_nodes.clear();
        graph_links.clear();
        node_name_to_id_map.clear();
        traced_processes.clear();
        traced_pids.clear();
        next_node_id = 0;
        next_link_id = 0;
        traced_process_name = path.substr(path.find_last_of("/\\") + 1);
        node_name_to_id_map[traced_process_name] = next_node_id;
        graph_nodes.push_back(GraphNode{next_node_id, traced_process_name});
        next_node_id++;
    }
    
    is_tracing = true;
    {
        std::lock_guard<std::mutex> lock(debugger_mutex);
        is_paused = false;
        single_step_mode = false;
        should_step = false;
        current_debug_pid = -1;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Child process - trace me
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(path.c_str(), path.c_str(), NULL);
        exit(1);
    } else {
        // Parent process - debugger
        current_debug_pid = child_pid;
        int status;
        
        // Wait for child to stop on exec
        waitpid(child_pid, &status, 0);
        
        if (WIFEXITED(status)) {
            std::lock_guard<std::mutex> lock(log_mutex);
            syscall_log.push_back("Error: Child process exited immediately.");
            is_tracing = false;
            return;
        }
        
        traced_processes[child_pid] = traced_process_name;
        traced_pids.push_back(child_pid);
        
        // Set options for better debugging
        ptrace(PTRACE_SETOPTIONS, child_pid, 0, 
               PTRACE_O_TRACESYSGOOD | 
               PTRACE_O_TRACEFORK | 
               PTRACE_O_TRACEVFORK | 
               PTRACE_O_TRACECLONE |
               PTRACE_O_TRACEEXEC);
        
        // Set initial breakpoint at entry point if we have file info
        FileParser* parser = get_active_parser();
        if (parser) {
            FileInfo info = parser->getInfo();
            if (info.entryPoint > 0) {
                if (set_breakpoint(child_pid, info.entryPoint)) {
                    std::lock_guard<std::mutex> lock(log_mutex);
                    syscall_log.push_back("Breakpoint set at entry point: 0x" + 
                                         std::to_string(info.entryPoint));
                }
            }
        }
        
        // Continue to entry point
        continue_execution(child_pid);
        
        while (is_tracing) {
            // Handle pause/resume
            {
                std::lock_guard<std::mutex> lock(debugger_mutex);
                if (is_paused && !should_step) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
            }
            
            pid_t current_pid = waitpid(-1, &status, __WCLONE);
            if (current_pid == -1) {
                if(traced_processes.empty()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            if (WIFEXITED(status)) {
                std::lock_guard<std::mutex> lock(log_mutex);
                syscall_log.push_back("Process " + std::to_string(current_pid) + " exited");
                traced_processes.erase(current_pid);
                traced_pids.erase(std::remove(traced_pids.begin(), traced_pids.end(), current_pid), traced_pids.end());
                if (traced_processes.empty()) break; 
                continue;
            }
            
            if (WIFSIGNALED(status)) {
                std::lock_guard<std::mutex> lock(log_mutex);
                syscall_log.push_back("Process " + std::to_string(current_pid) + " killed by signal");
                traced_processes.erase(current_pid);
                traced_pids.erase(std::remove(traced_pids.begin(), traced_pids.end(), current_pid), traced_pids.end());
                if (traced_processes.empty()) break; 
                continue;
            }

            // Check for breakpoint hit
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, current_pid, NULL, &regs);
                
                // Check if this is a breakpoint
                uint64_t breakpoint_addr = regs.rip - 1; // RIP points after INT3
                {
                    std::lock_guard<std::mutex> lock(breakpoints_mutex);
                    if (breakpoints.find(breakpoint_addr) != breakpoints.end()) {
                        // Breakpoint hit!
                        std::lock_guard<std::mutex> lock(log_mutex);
                        syscall_log.push_back("BREAKPOINT HIT at 0x" + std::to_string(breakpoint_addr));
                        
                        // Restore original instruction and single step
                        regs.rip = breakpoint_addr;
                        ptrace(PTRACE_SETREGS, current_pid, NULL, &regs);
                        ptrace(PTRACE_POKEDATA, current_pid, breakpoint_addr, breakpoints[breakpoint_addr].original_data);
                        
                        // Single step over the original instruction
                        single_step(current_pid);
                        waitpid(current_pid, &status, 0);
                        
                        // Restore breakpoint
                        long int3 = (breakpoints[breakpoint_addr].original_data & ~0xFF) | 0xCC;
                        ptrace(PTRACE_POKEDATA, current_pid, breakpoint_addr, int3);
                        
                        // Pause execution
                        {
                            std::lock_guard<std::mutex> debug_lock(debugger_mutex);
                            is_paused = true;
                        }
                        
                        std::lock_guard<std::mutex> log_lock(log_mutex);
                        syscall_log.push_back("--- PAUSED AT BREAKPOINT ---");
                        continue;
                    }
                }
            }

            // Handle process creation events
            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
                status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
                status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
                
                unsigned long new_pid;
                ptrace(PTRACE_GETEVENTMSG, current_pid, NULL, (long)&new_pid);
                
                std::string new_name = "child_" + std::to_string(new_pid);
                traced_processes[new_pid] = new_name;
                traced_pids.push_back(new_pid);
                
                {
                    std::lock_guard<std::mutex> lock(log_mutex);
                    syscall_log.push_back("EVENT: Process " + std::to_string(current_pid) + " created new process " + std::to_string(new_pid));
                }
                
                // Continue both processes
                ptrace(PTRACE_SYSCALL, current_pid, NULL, NULL);
                ptrace(PTRACE_SYSCALL, new_pid, NULL, NULL);
                continue;
            }

            // Handle syscall stops
            if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, current_pid, NULL, &regs);
                long syscall_num = regs.orig_rax;
                
                std::string log_line = "";
                std::string current_process_name = "unknown_pid";
                if (traced_processes.count(current_pid))
                     current_process_name = traced_processes[current_pid];

                if (syscall_num == __NR_openat) {
                    std::string filename = read_string_from_child(current_pid, regs.rsi);
                    log_line = "[PID " + std::to_string(current_pid) + "] openat: " + filename;
                } else if (syscall_num == __NR_execve) {
                    std::string filename = read_string_from_child(current_pid, regs.rdi);
                    log_line = "[PID " + std::to_string(current_pid) + "] execve: " + filename;
                    traced_processes[current_pid] = filename.substr(filename.find_last_of("/\\") + 1);
                } else if (syscall_map.count(syscall_num)) {
                    log_line = "[PID " + std::to_string(current_pid) + "] " + get_syscall_name(syscall_num);
                }
                
                if (!log_line.empty()) {
                    std::lock_guard<std::mutex> lock(log_mutex);
                    syscall_log.push_back(log_line);
                }
            }

            // If we're in single-step mode, pause after this instruction
            {
                std::lock_guard<std::mutex> lock(debugger_mutex);
                if (single_step_mode) {
                    is_paused = true;
                    should_step = false;
                    {
                        std::lock_guard<std::mutex> log_lock(log_mutex);
                        syscall_log.push_back("--- PAUSED AT INSTRUCTION ---");
                    }
                }
            }

            // Continue execution
            if (!is_paused) {
                ptrace(PTRACE_SYSCALL, current_pid, NULL, NULL);
            }
        }
    }

    std::lock_guard<std::mutex> lock(log_mutex);
    syscall_log.push_back("Debug session finished.");
    is_tracing = false;
    {
        std::lock_guard<std::mutex> lock(debugger_mutex);
        is_paused = false;
        single_step_mode = false;
        current_debug_pid = -1;
    }
}

// --- GRAPH HELPER FUNCTIONS ---
void auto_layout_graph() {
    std::lock_guard<std::mutex> lock(graph_mutex);
    
    if (graph_nodes.empty()) return;
    
    const float spacing = 150.0f;
    const int nodes_per_row = 3;
    int row = 0, col = 0;
    
    for (auto& node : graph_nodes) {
        ImNodes::SetNodeGridSpacePos(node.id, ImVec2(col * spacing, row * spacing));
        col++;
        if (col >= nodes_per_row) {
            col = 0;
            row++;
        }
    }
}

void clear_graph() {
    std::lock_guard<std::mutex> lock(graph_mutex);
    graph_nodes.clear();
    graph_links.clear();
    node_name_to_id_map.clear();
    next_node_id = 0;
    next_link_id = 0;
}

void remove_nodes_and_links(const std::vector<int>& node_ids) {
    std::lock_guard<std::mutex> lock(graph_mutex);
    
    graph_links.erase(
        std::remove_if(graph_links.begin(), graph_links.end(),
            [&](const GraphLink& link) {
                return std::find(node_ids.begin(), node_ids.end(), link.start_node) != node_ids.end() ||
                       std::find(node_ids.begin(), node_ids.end(), link.end_node) != node_ids.end();
            }),
        graph_links.end()
    );
    
    graph_nodes.erase(
        std::remove_if(graph_nodes.begin(), graph_nodes.end(),
            [&](const GraphNode& node) {
                return std::find(node_ids.begin(), node_ids.end(), node.id) != node_ids.end();
            }),
        graph_nodes.end()
    );
    
    for (auto it = node_name_to_id_map.begin(); it != node_name_to_id_map.end(); ) {
        if (std::find(node_ids.begin(), node_ids.end(), it->second) != node_ids.end()) {
            it = node_name_to_id_map.erase(it);
        } else {
            ++it;
        }
    }
}

void update_graph_from_log() {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::lock_guard<std::mutex> glock(graph_mutex);
    
    if (traced_processes.empty()) return; 

    for (size_t i = log_processed_index; i < syscall_log.size(); ++i) {
        const std::string& line = syscall_log[i];
        
        if (line[0] != '[') continue;
        size_t pid_end = line.find("]");
        if (pid_end == std::string::npos) continue;
        
        long pid_long = 0;
        try {
            pid_long = std::stol(line.substr(5, pid_end - 5));
        } catch (...) {
            continue;
        }
        pid_t pid = (pid_t)pid_long;
        
        std::string process_name = "unknown_pid";
        if(traced_processes.count(pid)) {
            process_name = traced_processes[pid];
        }

        if (node_name_to_id_map.find(process_name) == node_name_to_id_map.end()) {
            node_name_to_id_map[process_name] = next_node_id;
            graph_nodes.push_back(GraphNode{next_node_id, process_name});
            next_node_id++;
        }
        int process_node_id = node_name_to_id_map[process_name];

        std::string target_node_name = "";
        std::string connection_type = "";
        
        if (line.find("openat: ") != std::string::npos) {
            target_node_name = line.substr(line.find("openat: ") + 8);
            if (target_node_name.empty() || 
                target_node_name.rfind("/lib", 0) == 0 || 
                target_node_name.rfind("/etc", 0) == 0 ||
                target_node_name.rfind("/usr", 0) == 0) {
                continue;
            }
            connection_type = "file_access";
            
        } else if (line.find("connect: ") != std::string::npos) {
            target_node_name = "Network Connection";
            connection_type = "network";
            
        } else if (line.find("socket: ") != std::string::npos) {
            target_node_name = "Socket Creation";
            connection_type = "network";
            
        } else if (line.find("execve: ") != std::string::npos) {
            target_node_name = line.substr(line.find("execve: ") + 8);
            if (!target_node_name.empty()) {
                size_t last_slash = target_node_name.find_last_of("/\\");
                if (last_slash != std::string::npos) {
                    target_node_name = target_node_name.substr(last_slash + 1);
                }
                connection_type = "process_exec";
            }
            
        } else if (line.find("clone") != std::string::npos || 
                   line.find("fork") != std::string::npos) {
            target_node_name = "Process Creation";
            connection_type = "process_create";
        }
        
        if (!target_node_name.empty() && !connection_type.empty()) {
            std::string full_target_name = target_node_name + " (" + connection_type + ")";
            
            if (node_name_to_id_map.find(full_target_name) == node_name_to_id_map.end()) {
                node_name_to_id_map[full_target_name] = next_node_id;
                graph_nodes.push_back(GraphNode{next_node_id, full_target_name});
                next_node_id++;
            }
            int target_node_id = node_name_to_id_map[full_target_name];
            
            bool link_exists = false;
            for (const auto& link : graph_links) {
                if (link.start_node == process_node_id && link.end_node == target_node_id) {
                    link_exists = true;
                    break;
                }
            }
            
            if (!link_exists) {
                graph_links.push_back(GraphLink{next_link_id++, process_node_id, target_node_id});
            }
        }
        
        if (line.find("EVENT: Process") != std::string::npos && line.find("created new process") != std::string::npos) {
            size_t parent_start = line.find("Process ") + 8;
            size_t parent_end = line.find(" created");
            size_t child_start = line.find("process ") + 8;
            size_t child_end = line.length();
            
            if (parent_start != std::string::npos && parent_end != std::string::npos &&
                child_start != std::string::npos) {
                
                try {
                    pid_t parent_pid = std::stol(line.substr(parent_start, parent_end - parent_start));
                    pid_t child_pid = std::stol(line.substr(child_start, child_end - child_start));
                    
                    std::string parent_name = "unknown";
                    std::string child_name = "unknown";
                    
                    if (traced_processes.count(parent_pid)) parent_name = traced_processes[parent_pid];
                    if (traced_processes.count(child_pid)) child_name = traced_processes[child_pid];
                    
                    if (node_name_to_id_map.find(parent_name) == node_name_to_id_map.end()) {
                        node_name_to_id_map[parent_name] = next_node_id;
                        graph_nodes.push_back(GraphNode{next_node_id, parent_name});
                        next_node_id++;
                    }
                    if (node_name_to_id_map.find(child_name) == node_name_to_id_map.end()) {
                        node_name_to_id_map[child_name] = next_node_id;
                        graph_nodes.push_back(GraphNode{next_node_id, child_name});
                        next_node_id++;
                    }
                    
                    int parent_node_id = node_name_to_id_map[parent_name];
                    int child_node_id = node_name_to_id_map[child_name];
                    
                    bool link_exists = false;
                    for (const auto& link : graph_links) {
                        if (link.start_node == parent_node_id && link.end_node == child_node_id) {
                            link_exists = true;
                            break;
                        }
                    }
                    
                    if (!link_exists) {
                        graph_links.push_back(GraphLink{next_link_id++, parent_node_id, child_node_id});
                    }
                    
                } catch (...) {
                }
            }
        }
    }
    log_processed_index = syscall_log.size(); 
}

// --- STYLING ---
void ApplyFuturisticTheme() { 
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;
    style.WindowRounding = 5.0f;
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0;
    colors[ImGuiCol_Text]                   = ImVec4(0.95f, 0.96f, 0.98f, 1.00f);
    colors[ImGuiCol_TextDisabled]           = ImVec4(0.36f, 0.42f, 0.47f, 1.00f);
    colors[ImGuiCol_WindowBg]               = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_ChildBg]                = ImVec4(0.15f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_PopupBg]                = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
    colors[ImGuiCol_Border]                 = ImVec4(0.08f, 0.10f, 0.12f, 1.00f);
    colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]                = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.12f, 0.20f, 0.28f, 1.00f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(0.09f, 0.12f, 0.14f, 1.00f);
    colors[ImGuiCol_TitleBg]                = ImVec4(0.09f, 0.12f, 0.14f, 0.65f);
    colors[ImGuiCol_TitleBgActive]          = ImVec4(0.08f, 0.10f, 0.12f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]       = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
    colors[ImGuiCol_MenuBarBg]              = ImVec4(0.15f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.02f, 0.02f, 0.02f, 0.39f);
    colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.18f, 0.22f, 0.25f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.00f, 0.78f, 0.61f, 1.00f);
    colors[ImGuiCol_CheckMark]              = ImVec4(0.00f, 0.78f, 0.61f, 1.00f);
    colors[ImGuiCol_SliderGrab]             = ImVec4(0.00f, 0.78f, 0.61f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.00f, 0.98f, 0.76f, 1.00f);
    colors[ImGuiCol_Button]                 = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_ButtonHovered]          = ImVec4(0.00f, 0.78f, 0.61f, 1.00f);
    colors[ImGuiCol_ButtonActive]           = ImVec4(0.00f, 0.98f, 0.76f, 1.00f);
    colors[ImGuiCol_Header]                 = ImVec4(0.20f, 0.25f, 0.29f, 0.55f);
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.00f, 0.78f, 0.61f, 1.00f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.00f, 0.78f, 0.61f, 1.00f);
    colors[ImGuiCol_Separator]              = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_SeparatorHovered]       = ImVec4(0.10f, 0.40f, 0.75f, 0.78f);
    colors[ImGuiCol_SeparatorActive]        = ImVec4(0.10f, 0.40f, 0.75f, 1.00f);
    colors[ImGuiCol_ResizeGrip]             = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);
    colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
    colors[ImGuiCol_Tab]                    = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_TabHovered]             = ImVec4(0.00f, 0.78f, 0.61f, 0.80f);
    colors[ImGuiCol_TabActive]              = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_TabUnfocused]           = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive]     = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_DockingPreview]         = ImVec4(0.00f, 0.78f, 0.61f, 0.70f);
    colors[ImGuiCol_DockingEmptyBg]         = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_PlotLines]              = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
    colors[ImGuiCol_PlotLinesHovered]       = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
    colors[ImGuiCol_PlotHistogram]          = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
    colors[ImGuiCol_PlotHistogramHovered]   = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
    colors[ImGuiCol_TextSelectedBg]         = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    colors[ImGuiCol_DragDropTarget]         = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
    colors[ImGuiCol_NavHighlight]           = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_NavWindowingHighlight]  = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg]      = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg]       = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);
}

// --- FILE DIALOG ---
std::string open_file_dialog() {
    nfdchar_t* outPath = nullptr;
    nfdresult_t result = NFD_OpenDialog(nullptr, nullptr, &outPath);
    if (result == NFD_OKAY) {
        std::string path(outPath);
        free(outPath);
        return path;
    }
    return "";
}

// --- MENU BAR ---
void show_menu_bar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open Static File")) {
                std::string path = open_file_dialog();
                if (!path.empty()) {
                    auto parser = create_parser(path);
                    if (!parser) {
                        fprintf(stderr, "Failed to parse file: %s\n", path.c_str());
                    } else {
                        FileAnalysisSession session;
                        session.path = path;
                        session.filename = path.substr(path.find_last_of("/\\") + 1);
                        session.parser = std::move(parser);
                        loaded_files.push_back(std::move(session));
                        active_file_index = loaded_files.size() - 1; 
                        show_loaded_files_window = true; 
                        show_summary_window = true;
                    }
                }
            }
            ImGui::MenuItem("Show Loaded Files", NULL, &show_loaded_files_window);
            if (ImGui::MenuItem("Exit")) {
                SDL_Event ev; ev.type = SDL_QUIT; SDL_PushEvent(&ev);
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Static Analysis")) {
            bool enabled = active_file_index != -1;
            ImGui::MenuItem("Summary", NULL, &show_summary_window, enabled);
            ImGui::MenuItem("Sections", NULL, &show_sections_window, enabled);
            ImGui::MenuItem("Entropy", NULL, &show_entropy_window, enabled);
            ImGui::MenuItem("Imports", NULL, &show_imports_window, enabled);
            ImGui::MenuItem("Strings", NULL, &show_strings_window, enabled);
            ImGui::MenuItem("Disassembly", NULL, &show_disassembly_window, enabled);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Dynamic Analysis")) {
            ImGui::MenuItem("Graph View", NULL, &show_graph_view_window);
            ImGui::MenuItem("Debugger", NULL, &show_debugger_window);
            ImGui::MenuItem("Registers", NULL, &show_registers_window);
            ImGui::MenuItem("Memory", NULL, &show_memory_window);
            ImGui::MenuItem("Breakpoints", NULL, &show_breakpoints_window);
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }
}

// --- DOCKSPACE ---
void setup_dockspace() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGuiID dockspace_id = ImGui::GetID("MyDockSpace");
    ImGui::DockSpaceOverViewport(dockspace_id, viewport, ImGuiDockNodeFlags_None);

    if (!g_DockspaceInitialized) {
        if (ImGui::GetFrameCount() > 1) {
            ImGui::DockBuilderRemoveNode(dockspace_id);
            ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
            ImGui::DockBuilderSetNodeSize(dockspace_id, viewport->Size);
            
            ImGuiID main_id = dockspace_id;
            ImGuiID left = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Left, 0.2f, nullptr, &main_id);
            ImGuiID bottom = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.3f, nullptr, &main_id);
            
            ImGui::DockBuilderDockWindow("Graph View", main_id);
            ImGui::DockBuilderDockWindow("Debugger", bottom);
            ImGui::DockBuilderDockWindow("Loaded Files", left);
            
            ImGui::DockBuilderDockWindow("Summary", left);
            ImGui::DockBuilderDockWindow("Sections", left);
            ImGui::DockBuilderDockWindow("Entropy", left);
            ImGui::DockBuilderDockWindow("Imports", left);
            ImGui::DockBuilderDockWindow("Strings", left);
            ImGui::DockBuilderDockWindow("Disassembly", left);
            ImGui::DockBuilderDockWindow("Registers", left);
            ImGui::DockBuilderDockWindow("Memory", left);
            ImGui::DockBuilderDockWindow("Breakpoints", left);

            ImGui::DockBuilderFinish(dockspace_id);
            g_DockspaceInitialized = true;
        }
    }
}

// --- INDIVIDUAL RENDER FUNCTIONS ---
void render_loaded_files_window() {
    ImGui::Text("Loaded Files");
    ImGui::Separator();
    ImGui::Text("Select a file for static analysis:");
    ImGui::BeginChild("FileList");
    for (int i = 0; i < loaded_files.size(); ++i) {
        if (ImGui::Selectable(loaded_files[i].filename.c_str(), active_file_index == i)) {
            active_file_index = i;
        }
    }
    ImGui::EndChild();
}

FileParser* get_active_parser() {
    if (active_file_index < 0 || active_file_index >= (int)loaded_files.size()) {
        return nullptr;
    }
    return loaded_files[active_file_index].parser.get();
}

void render_summary_content() {
    FileParser* parser = get_active_parser();
    if (!parser) { ImGui::Text("No file selected."); return; }
    FileInfo info = parser->getInfo();
    ImGui::Text("File Type:    %s", info.type.c_str());
    ImGui::Text("Architecture: %s", info.architecture.c_str());
    ImGui::Text("Entry Point:  0x%llX", (unsigned long long)info.entryPoint);
    ImGui::Text("File Size:    %lld bytes", (long long)info.fileSize);
    ImGui::Text("File Entropy: %.4f (max 8.0)", info.fileEntropy);
    ImGui::Separator();
    ImGui::Text("MD5:");
    ImGui::InputText("##md5", (char*)info.md5.c_str(), info.md5.length() + 1, ImGuiInputTextFlags_ReadOnly);
    ImGui::Text("SHA1:");
    ImGui::InputText("##sha1", (char*)info.sha1.c_str(), info.sha1.length() + 1, ImGuiInputTextFlags_ReadOnly);
    ImGui::Text("SHA256:");
    ImGui::InputText("##sha256", (char*)info.sha256.c_str(), info.sha256.length() + 1, ImGuiInputTextFlags_ReadOnly);
}

void render_sections_content() {
    FileParser* parser = get_active_parser();
    if (!parser) { ImGui::Text("No file selected."); return; }
    FileInfo info = parser->getInfo();
    ImGui::Columns(5, "SectionColumns");
    ImGui::Separator();
    ImGui::Text("Name"); ImGui::NextColumn();
    ImGui::Text("VA"); ImGui::NextColumn();
    ImGui::Text("VS"); ImGui::NextColumn();
    ImGui::Text("RPtr"); ImGui::NextColumn();
    ImGui::Text("RS"); ImGui::NextColumn();
    ImGui::Separator();
    for (const auto& sec : info.sections) {
        ImGui::Text("%s", sec.name.c_str()); ImGui::NextColumn();
        ImGui::Text("0x%llX", (unsigned long long)sec.virtualAddress); ImGui::NextColumn();
        ImGui::Text("0x%llX", (unsigned long long)sec.virtualSize); ImGui::NextColumn();
        ImGui::Text("0x%llX", (unsigned long long)sec.rawDataPtr); ImGui::NextColumn();
        ImGui::Text("0x%llX", (unsigned long long)sec.rawDataSize); ImGui::NextColumn();
    }
    ImGui::Columns(1);
}

void render_entropy_content() {
    FileParser* parser = get_active_parser();
    if (!parser) { ImGui::Text("No file selected."); return; }
    FileInfo info = parser->getInfo();
    ImGui::Text("Overall File Entropy: %.4f", info.fileEntropy);
    ImGui::Separator();
    ImGui::Text("Section Entropy (high entropy > 7.0 suggests packing/encryption):");
    ImGui::Columns(2, "EntropyColumns");
    ImGui::Separator();
    ImGui::Text("Section Name"); ImGui::NextColumn();
    ImGui::Text("Entropy"); ImGui::NextColumn();
    ImGui::Separator();
    for (const auto& sec : info.sections) {
        ImGui::Text("%s", sec.name.c_str()); ImGui::NextColumn();
        ImGui::Text("%.4f", sec.entropy); ImGui::NextColumn();
    }
    ImGui::Columns(1);
}

void render_imports_content() {
    FileParser* parser = get_active_parser();
    if (!parser) { ImGui::Text("No file selected."); return; }
    FileInfo info = parser->getInfo();
    if (info.imports.empty()) {
        ImGui::Text("No import data found (or not a PE file).");
        return;
    }
    for (const auto& import : info.imports) {
        if (ImGui::TreeNode(import.dll_name.c_str())) {
            for (const auto& func : import.function_names) {
                ImGui::BulletText("%s", func.c_str());
            }
            ImGui::TreePop();
        }
    }
}

void render_strings_content() {
    FileParser* parser = get_active_parser();
    if (!parser) { ImGui::Text("No file selected."); return; }
    FileInfo info = parser->getInfo();
    ImGui::BeginChild("StringList");
    for (const auto& str : info.strings) {
        ImGui::TextWrapped("%s", str.c_str());
    }
    ImGui::EndChild();
}

void render_static_disassembly_content() {
    FileParser* parser = get_active_parser();
    if (!parser) { ImGui::Text("No file selected."); return; }
    FileInfo info = parser->getInfo();
    ImGui::BeginChild("DisassemblyList");
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.back()); 
    for (const auto& line : info.disassembly) {
        ImGui::TextUnformatted(line.c_str());
    }
    ImGui::PopFont();
    ImGui::EndChild();
}

// --- NEW DEBUGGER WINDOWS ---
void render_registers_window() {
    if (!is_tracing || current_debug_pid == -1) {
        ImGui::Text("No active debug session");
        return;
    }
    
    struct user_regs_struct regs = get_registers(current_debug_pid);
    
    ImGui::Columns(2, "Registers");
    ImGui::Text("RAX: 0x%016llx", regs.rax); ImGui::NextColumn();
    ImGui::Text("RBX: 0x%016llx", regs.rbx); ImGui::NextColumn();
    ImGui::Text("RCX: 0x%016llx", regs.rcx); ImGui::NextColumn();
    ImGui::Text("RDX: 0x%016llx", regs.rdx); ImGui::NextColumn();
    ImGui::Text("RSI: 0x%016llx", regs.rsi); ImGui::NextColumn();
    ImGui::Text("RDI: 0x%016llx", regs.rdi); ImGui::NextColumn();
    ImGui::Text("RBP: 0x%016llx", regs.rbp); ImGui::NextColumn();
    ImGui::Text("RSP: 0x%016llx", regs.rsp); ImGui::NextColumn();
    ImGui::Text("RIP: 0x%016llx", regs.rip); ImGui::NextColumn();
    ImGui::Text("R8:  0x%016llx", regs.r8); ImGui::NextColumn();
    ImGui::Text("R9:  0x%016llx", regs.r9); ImGui::NextColumn();
    ImGui::Text("R10: 0x%016llx", regs.r10); ImGui::NextColumn();
    ImGui::Text("R11: 0x%016llx", regs.r11); ImGui::NextColumn();
    ImGui::Text("R12: 0x%016llx", regs.r12); ImGui::NextColumn();
    ImGui::Text("R13: 0x%016llx", regs.r13); ImGui::NextColumn();
    ImGui::Text("R14: 0x%016llx", regs.r14); ImGui::NextColumn();
    ImGui::Text("R15: 0x%016llx", regs.r15); ImGui::NextColumn();
    ImGui::Columns(1);
}

void render_memory_window() {
    if (!is_tracing || current_debug_pid == -1) {
        ImGui::Text("No active debug session");
        return;
    }
    
    static uint64_t memory_address = 0x400000;
    static int memory_size = 64;
    
    ImGui::InputScalar("Address", ImGuiDataType_U64, &memory_address);
    ImGui::InputInt("Size", &memory_size);
    memory_size = std::max(16, std::min(memory_size, 1024));
    
    if (ImGui::Button("Read Memory")) {
        // Memory reading happens in the display
    }
    
    ImGui::Separator();
    
    std::string memory_data = read_memory(current_debug_pid, memory_address, memory_size);
    
    ImGui::BeginChild("MemoryView");
    for (size_t i = 0; i < memory_data.size(); i += 16) {
        ImGui::Text("0x%08lx: ", memory_address + i);
        ImGui::SameLine();
        
        // Hex dump
        for (size_t j = 0; j < 16 && (i + j) < memory_data.size(); j++) {
            if (j > 0) ImGui::SameLine();
            ImGui::Text("%02x ", (unsigned char)memory_data[i + j]);
        }
        
        ImGui::SameLine(300);
        
        // ASCII dump
        for (size_t j = 0; j < 16 && (i + j) < memory_data.size(); j++) {
            char c = memory_data[i + j];
            if (isprint(c)) {
                ImGui::Text("%c", c);
            } else {
                ImGui::Text(".");
            }
            if (j < 15) ImGui::SameLine();
        }
    }
    ImGui::EndChild();
}

void render_breakpoints_window() {
    if (!is_tracing || current_debug_pid == -1) {
        ImGui::Text("No active debug session");
        return;
    }
    
    static uint64_t new_breakpoint_addr = 0x400000;
    
    ImGui::InputScalar("Breakpoint Address", ImGuiDataType_U64, &new_breakpoint_addr);
    
    if (ImGui::Button("Set Breakpoint")) {
        if (set_breakpoint(current_debug_pid, new_breakpoint_addr)) {
            std::lock_guard<std::mutex> lock(log_mutex);
            syscall_log.push_back("Breakpoint set at 0x" + std::to_string(new_breakpoint_addr));
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Active Breakpoints:");
    
    std::lock_guard<std::mutex> lock(breakpoints_mutex);
    for (auto& [addr, bp] : breakpoints) {
        ImGui::Text("0x%lx", addr);
        ImGui::SameLine();
        if (ImGui::SmallButton(("Remove##" + std::to_string(addr)).c_str())) {
            remove_breakpoint(current_debug_pid, addr);
        }
    }
}

void render_live_disassembly_window() {
    if (!is_tracing || current_debug_pid == -1) {
        ImGui::Text("No active debug session");
        return;
    }
    
    struct user_regs_struct regs = get_registers(current_debug_pid);
    static uint64_t disasm_address = 0x400000;
    
    if (ImGui::Button("Show at RIP")) {
        disasm_address = regs.rip;
    }
    ImGui::SameLine();
    ImGui::InputScalar("Address", ImGuiDataType_U64, &disasm_address);
    
    ImGui::Separator();
    
    std::vector<std::string> instructions = disassemble_at_address(current_debug_pid, disasm_address, 20);
    
    ImGui::BeginChild("DisassemblyView");
    for (const auto& instr : instructions) {
        // Highlight current instruction
        if (disasm_address == regs.rip && instr.find(std::to_string(regs.rip)) != std::string::npos) {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "> %s", instr.c_str());
        } else {
            ImGui::Text("%s", instr.c_str());
        }
    }
    ImGui::EndChild();
}

// Update the debugger window to include new features
void render_debugger_window() {
    ImGui::Text("DANGER: This is NOT a sandbox. Debugged programs run live on your system.");
    
    // Debugger control buttons
    if (!is_tracing) {
        if (ImGui::Button("Start Debug")) {
            FileParser* parser = get_active_parser();
            if (parser) {
                if(tracer_thread.joinable()) tracer_thread.join();
                tracer_thread = std::thread(debug_program, loaded_files[active_file_index].path);
            } else {
                ImGui::Text("No active file selected to debug!");
            }
        }
    } else {
        // Debugging controls
        if (is_paused) {
            if (ImGui::Button("Resume")) {
                resume_trace();
            }
            ImGui::SameLine();
            if (ImGui::Button("Step")) {
                step_trace();
            }
        } else {
            if (ImGui::Button("Pause")) {
                pause_trace();
            }
        }
        
        ImGui::SameLine();
        if (ImGui::Button("Stop Debug")) { 
            is_tracing = false; 
            if(tracer_thread.joinable()) tracer_thread.join();
        }
        
        // Single step mode toggle
        ImGui::SameLine();
        if (ImGui::Checkbox("Single Step", &single_step_mode)) {
            set_single_step_mode(single_step_mode);
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Clear Log")) {
        std::lock_guard<std::mutex> lock(log_mutex);
        syscall_log.clear();
        log_processed_index = 0;
        std::lock_guard<std::mutex> glock(graph_mutex);
        graph_nodes.clear();
        graph_links.clear();
        node_name_to_id_map.clear();
        traced_processes.clear();
        traced_pids.clear();
        next_node_id = 0;
        next_link_id = 0;
    }
    
    // Show debugger status
    ImGui::SameLine();
    if (is_tracing) {
        if (is_paused) {
            ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "PAUSED");
        } else {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "RUNNING");
        }
        ImGui::SameLine();
        ImGui::Text("| PID: %d", current_debug_pid);
    }
    
    ImGui::Separator();
    
    // Debugger tabs
    if (ImGui::BeginTabBar("DebuggerTabs")) {
        if (ImGui::BeginTabItem("Log")) {
            ImGui::BeginChild("SyscallLog");
            ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.back());
            {
                std::lock_guard<std::mutex> lock(log_mutex);
                for (const auto& line : syscall_log) {
                    if (line.find("PAUSED") != std::string::npos) {
                        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%s", line.c_str());
                    } else if (line.find("BREAKPOINT") != std::string::npos) {
                        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "%s", line.c_str());
                    } else if (line.find("Starting debug") != std::string::npos || 
                               line.find("Debug session finished") != std::string::npos) {
                        ImGui::TextColored(ImVec4(0.0f, 1.0f, 1.0f, 1.0f), "%s", line.c_str());
                    } else if (line.find("EVENT:") != std::string::npos) {
                        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "%s", line.c_str());
                    } else if (line.find("Error:") != std::string::npos) {
                        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "%s", line.c_str());
                    } else {
                        ImGui::TextUnformatted(line.c_str());
                    }
                }
            }
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
            ImGui::PopFont();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        
        if (ImGui::BeginTabItem("Registers")) {
            render_registers_window();
            ImGui::EndTabItem();
        }
        
        if (ImGui::BeginTabItem("Memory")) {
            render_memory_window();
            ImGui::EndTabItem();
        }
        
        if (ImGui::BeginTabItem("Disassembly")) {
            render_live_disassembly_window();
            ImGui::EndTabItem();
        }
        
        if (ImGui::BeginTabItem("Breakpoints")) {
            render_breakpoints_window();
            ImGui::EndTabItem();
        }
        
        ImGui::EndTabBar();
    }
}

// FIXED: Functional Graph View Window
void render_graph_view_window() {
    ImGui::Text("Dynamic Analysis Graph");
    ImGui::SameLine();
    
    // Add functional buttons
    if (ImGui::SmallButton("Auto-layout")) {
        auto_layout_graph();
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear Graph")) {
        clear_graph();
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Fit View")) {
        // This would center and zoom to fit all nodes
    }

    if (!g_DockspaceInitialized) {
        ImGui::Text("Initializing Dockspace...");
        return;
    }
    
    // Disable error check temporarily
    ImGuiContext& g = *ImGui::GetCurrentContext();
    bool backup_io_config_windows_move_from_title_bar_only = g.IO.ConfigWindowsMoveFromTitleBarOnly;
    g.IO.ConfigWindowsMoveFromTitleBarOnly = true;
    
    ImVec2 window_size = ImGui::GetContentRegionAvail();
    if (window_size.y < 300.0f) window_size.y = 300.0f;
    
    ImGui::PushID("GraphViewChild");
    ImGui::BeginChild("GraphViewChild", window_size, true, 
                     ImGuiWindowFlags_NoMove | 
                     ImGuiWindowFlags_AlwaysVerticalScrollbar | 
                     ImGuiWindowFlags_AlwaysHorizontalScrollbar);
    
    ImGui::Dummy(ImVec2(10, 10));
    
    ImNodes::BeginNodeEditor();
    
    std::lock_guard<std::mutex> glock(graph_mutex);
    
    // Render all nodes with proper attributes
    for (const auto& node : graph_nodes) {
        ImNodes::BeginNode(node.id);
        
        // Node title
        ImNodes::BeginNodeTitleBar();
        ImGui::TextUnformatted(node.label.c_str());
        ImNodes::EndNodeTitleBar();
        
        // Input attribute (left side)
        ImNodes::BeginInputAttribute(node.id * 1000);
        ImGui::Text("In");
        ImNodes::EndInputAttribute();
        
        ImGui::SameLine();
        
        // Output attribute (right side)
        ImNodes::BeginOutputAttribute(node.id * 1000 + 1);
        ImGui::Text("Out");
        ImNodes::EndOutputAttribute();
        
        // Add some node content
        ImGui::Text("PID: %d", node.id);
        if (node.label.find("Network") != std::string::npos) {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.5f, 1.0f), "NETWORK");
        } else if (node.label.find("openat:") != std::string::npos) {
            ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "FILE I/O");
        } else if (node.label.find("child_") != std::string::npos) {
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 1.0f, 1.0f), "CHILD PROC");
        }
        
        ImNodes::EndNode();
    }
    
    // Render all links
    for (const auto& link : graph_links) {
        // Use proper attribute IDs for connections
        ImNodes::Link(link.id, 
                     link.start_node * 1000 + 1,  // Output attribute of start node
                     link.end_node * 1000);       // Input attribute of end node
    }
    
    ImNodes::EndNodeEditor();
    
    // Check for selected nodes (for deletion or other operations)
    const int num_selected_nodes = ImNodes::NumSelectedNodes();
    if (num_selected_nodes > 0 && ImGui::IsKeyPressed(ImGuiKey_Delete)) {
        std::vector<int> selected_nodes;
        selected_nodes.resize(num_selected_nodes);
        ImNodes::GetSelectedNodes(selected_nodes.data());
        
        // Remove selected nodes and their links
        remove_nodes_and_links(selected_nodes);
    }
    
    ImGui::Dummy(ImVec2(10, 10));
    ImGui::EndChild();
    ImGui::PopID();
    
    // Restore the config
    g.IO.ConfigWindowsMoveFromTitleBarOnly = backup_io_config_windows_move_from_title_bar_only;
    
    // Show graph statistics
    ImGui::Text("Nodes: %zu | Links: %zu | Processes: %zu", 
                graph_nodes.size(), graph_links.size(), traced_processes.size());
}

// --- MAIN FUNCTION ---
int main(int, char**) {
    // --- Init SDL, OpenGL, ImGui ---
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) { return -1; }
    const char* glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_Window* window = SDL_CreateWindow("Malware Analysis Framework", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                          1280, 720, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1);
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImNodes::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    ApplyFuturisticTheme(); 
    ImFont* mono_font = io.Fonts->AddFontFromFileTTF("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14.0f);
    if (mono_font == nullptr) {
        fprintf(stderr, "Warning: Could not load monospace font.\n");
        io.Fonts->AddFontDefault();
    }
    ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // --- Main Loop ---
    bool done = false;
    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) done = true;
        }

        // Handle keyboard shortcuts for debugger
        if (ImGui::GetIO().WantCaptureKeyboard) {
            // Only process if ImGui isn't using the keyboard
        } else {
            const Uint8* state = SDL_GetKeyboardState(NULL);
            if (state[SDL_SCANCODE_F5] && is_tracing) {
                if (is_paused) {
                    resume_trace();
                } else {
                    pause_trace();
                }
                SDL_Delay(100);
            }
            if (state[SDL_SCANCODE_F10] && is_tracing && is_paused) {
                step_trace();
                SDL_Delay(100);
            }
            if (state[SDL_SCANCODE_F11] && is_tracing) {
                single_step_mode = !single_step_mode;
                set_single_step_mode(single_step_mode);
                SDL_Delay(100);
            }
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        setup_dockspace();
        show_menu_bar();

        if (is_tracing) {
            update_graph_from_log();
        }

        // --- Render all windows ---
        if (show_loaded_files_window) {
            ImGui::Begin("Loaded Files", &show_loaded_files_window);
            render_loaded_files_window();
            ImGui::End();
        }

        if (show_graph_view_window) {
            ImGui::Begin("Graph View", &show_graph_view_window); 
            render_graph_view_window();
            ImGui::End();
        }
        
        if (show_debugger_window) {
            ImGui::Begin("Debugger", &show_debugger_window); 
            render_debugger_window();
            ImGui::End();
        }

        if (show_registers_window) {
            ImGui::Begin("Registers", &show_registers_window);
            render_registers_window();
            ImGui::End();
        }

        if (show_memory_window) {
            ImGui::Begin("Memory", &show_memory_window);
            render_memory_window();
            ImGui::End();
        }

        if (show_breakpoints_window) {
            ImGui::Begin("Breakpoints", &show_breakpoints_window);
            render_breakpoints_window();
            ImGui::End();
        }

        FileParser* activeParser = get_active_parser();
        if (activeParser) {
            if (show_summary_window) {
                ImGui::Begin("Summary", &show_summary_window); 
                render_summary_content(); 
                ImGui::End();
            }
            if (show_sections_window) {
                ImGui::Begin("Sections", &show_sections_window); 
                render_sections_content(); 
                ImGui::End();
            }
            if (show_entropy_window) {
                ImGui::Begin("Entropy", &show_entropy_window); 
                render_entropy_content(); 
                ImGui::End();
            }
            if (show_imports_window) {
                ImGui::Begin("Imports", &show_imports_window); 
                render_imports_content(); 
                ImGui::End();
            }
            if (show_strings_window) {
                ImGui::Begin("Strings", &show_strings_window); 
                render_strings_content(); 
                ImGui::End();
            }
            if (show_disassembly_window) {
                ImGui::Begin("Disassembly", &show_disassembly_window); 
                render_static_disassembly_content(); 
                ImGui::End();
            }
        }

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.11f, 0.15f, 0.17f, 1.00f); 
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
            SDL_Window* backup_win = SDL_GL_GetCurrentWindow();
            SDL_GLContext backup_ctx = SDL_GL_GetCurrentContext();
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
            SDL_GL_MakeCurrent(backup_win, backup_ctx);
        }
        SDL_GL_SwapWindow(window);
    }

    // --- Cleanup ---
    is_tracing = false; 
    if(tracer_thread.joinable()) tracer_thread.join();
    ImNodes::DestroyContext(); 
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}