// main.cpp
#include "imgui.h"
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"
#include "imgui_internal.h"

#include <SDL.h>
#include <SDL_opengl.h>
#include <SDL_image.h>
#include <GL/gl.h>
#include <stdio.h>
#include <string>

#define NFD_THROWS_EXCEPTIONS
#include "nativefiledialog/src/include/nfd.h"
#include "pe_headers.h"

std::string selected_file;
GLuint file_icon_texture = 0;

bool load_icon_texture(const char* path, GLuint* out_texture, int* out_width, int* out_height) {
    SDL_Surface* surface = IMG_Load(path);
    if (!surface) return false;

    GLuint texture;
    glGenTextures(1, &texture);
    glBindTexture(GL_TEXTURE_2D, texture);

    GLint mode = surface->format->BytesPerPixel == 4 ? GL_RGBA : GL_RGB;

    glTexImage2D(GL_TEXTURE_2D, 0, mode, surface->w, surface->h, 0, mode, GL_UNSIGNED_BYTE, surface->pixels);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    *out_texture = texture;
    *out_width = surface->w;
    *out_height = surface->h;

    SDL_FreeSurface(surface);
    return true;
}

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

void render_graph_view() {
    ImGui::Text("Graph View Placeholder");
}

void render_pe_inspector() {
    ImGui::BeginTabBar("PE Tabs");
    if (ImGui::BeginTabItem("Headers")) {
        render_pe_headers_tab();
        ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Imports")) {
        ImGui::Text("PE Imports...");
        ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Strings")) {
        ImGui::Text("PE Strings...");
        ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Entropy")) {
        ImGui::Text("PE Entropy...");
        ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
}

void render_debugger_console() {
    static char buffer[1024] = {};
    ImGui::InputTextMultiline("##console", buffer, IM_ARRAYSIZE(buffer), ImVec2(-FLT_MIN, -FLT_MIN));
}

void render_decompiled_code() {
    ImGui::Text("Decompiled code display...");
}

void show_loaded_file_name() {
    if (!selected_file.empty() && file_icon_texture != 0) {
        static ImVec2 icon_pos = ImVec2(300, 300);
        static bool dragging = false;
        static ImVec2 drag_offset = ImVec2(0, 0);

        float scale = 4.0f;
        ImVec2 icon_size = ImVec2(100 * scale, 100 * scale);
        ImVec2 icon_end = ImVec2(icon_pos.x + icon_size.x, icon_pos.y + icon_size.y);
        ImVec2 mouse = ImGui::GetIO().MousePos;

        ImDrawList* draw_list = ImGui::GetForegroundDrawList();
        draw_list->AddImage((ImTextureID)(intptr_t)file_icon_texture, icon_pos, icon_end);

        bool hovered = mouse.x >= icon_pos.x && mouse.x <= icon_end.x &&
                       mouse.y >= icon_pos.y && mouse.y <= icon_end.y;

        if (hovered && ImGui::IsMouseClicked(0)) {
            dragging = true;
            drag_offset = ImVec2(mouse.x - icon_pos.x, mouse.y - icon_pos.y);
        }

        if (!ImGui::IsMouseDown(0)) {
            dragging = false;
        }

        if (dragging) {
            icon_pos = ImVec2(mouse.x - drag_offset.x, mouse.y - drag_offset.y);
            icon_end = ImVec2(icon_pos.x + icon_size.x, icon_pos.y + icon_size.y);
        }

        std::string filename = selected_file.substr(selected_file.find_last_of("/\\") + 1);
        ImVec2 text_size = ImGui::CalcTextSize(filename.c_str());
        ImVec2 text_pos = ImVec2(icon_pos.x + (icon_size.x - text_size.x) * 0.5f, icon_end.y + 5.0f);
        draw_list->AddText(text_pos, IM_COL32(255, 255, 255, 255), filename.c_str());
    }
}

void show_menu_bar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open")) {
                std::string path = open_file_dialog();
                if (!path.empty()) {
                    selected_file = path;
                    parse_pe_headers(path);
                }
            }
            if (ImGui::MenuItem("Exit")) {
                SDL_Event ev;
                ev.type = SDL_QUIT;
                SDL_PushEvent(&ev);
            }
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }
}

void setup_dockspace() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGuiID dockspace_id = ImGui::GetID("MyDockSpace");

    ImGui::DockSpaceOverViewport(dockspace_id, viewport);

    static bool initialized = false;
    if (!initialized) {
        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dockspace_id, viewport->Size);

        ImGuiID main_id = dockspace_id;
        ImGuiID right = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Right, 0.3f, nullptr, &main_id);
        ImGuiID bottom = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.3f, nullptr, &main_id);
        ImGuiID bottom_right = ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.5f, nullptr, &right);

        ImGui::DockBuilderDockWindow("Graph View", main_id);
        ImGui::DockBuilderDockWindow("PE Inspector", right);
        ImGui::DockBuilderDockWindow("Debugger Console", bottom);
        ImGui::DockBuilderDockWindow("Decompiled Code", bottom_right);

        ImGui::DockBuilderFinish(dockspace_id);
        initialized = true;
    }
}

void render() {
    setup_dockspace();
    show_menu_bar();
    show_loaded_file_name();

    ImGui::Begin("Graph View");
    render_graph_view();
    ImGui::End();

    ImGui::Begin("PE Inspector");
    render_pe_inspector();
    ImGui::End();

    ImGui::Begin("Debugger Console");
    render_debugger_console();
    ImGui::End();

    ImGui::Begin("Decompiled Code");
    render_decompiled_code();
    ImGui::End();
}

int main(int, char**) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) != 0) {
        printf("Error: %s\n", SDL_GetError());
        return -1;
    }

    if (!(IMG_Init(IMG_INIT_PNG) & IMG_INIT_PNG)) {
        printf("Failed to init SDL_image\n");
        return -1;
    }

    const char* glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);

    SDL_Window* window = SDL_CreateWindow("Malware GUI", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                          1280, 720, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

    ImGui::StyleColorsDark();
    ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    int w, h;
    if (!load_icon_texture("/root/malware_graph_gui/icon/icon.png", &file_icon_texture, &w, &h)) {
        fprintf(stderr, "Failed to load icon/icon.png\n");
    }

    bool done = false;
    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) done = true;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        render();

        ImGui::Render();
        SDL_GL_MakeCurrent(window, gl_context);
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
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

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    IMG_Quit();
    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
