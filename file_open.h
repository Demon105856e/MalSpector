// file_open.h
#pragma once
#include <string>
#include <imgui.h>
#include "nativefiledialog/src/include/nfd.h"


inline std::string selected_file;

inline std::string open_file_dialog() {
    nfdchar_t* outPath = nullptr;
    nfdresult_t result = NFD_OpenDialog(nullptr, nullptr, &outPath);

    if (result == NFD_OKAY) {
        std::string filePath(outPath);
        free(outPath);
        return filePath;
    } else if (result == NFD_CANCEL) {
        return "";
    } else {
        return "Error: " + std::string(NFD_GetError());
    }
}

inline void show_menu_bar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open")) {
                selected_file = open_file_dialog();
            }
            if (ImGui::MenuItem("Exit")) {
                exit(0);
            }
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }
}

inline void show_loaded_file_name() {
    if (!selected_file.empty()) {
        ImGui::Begin("Loaded File");
        ImGui::Text("Selected file: %s", selected_file.c_str());
        ImGui::End();
    }
}
