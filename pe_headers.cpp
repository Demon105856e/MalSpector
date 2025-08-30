#include "pe_headers.h"
#include "imgui.h"
#include <fstream>
#include <cstring>
#include <stdexcept>

PEHeadersInfo peInfo;

bool PEParser::load(const std::string& path) {
    clear();
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;

    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    if (size < 0x100) return false;

    file.seekg(0, std::ios::beg);
    data.resize(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    return parse();
}

bool PEParser::parse() {
    if (data.size() < 0x100) return false;

    uint16_t e_magic = *reinterpret_cast<uint16_t*>(&data[0]);
    if (e_magic != 0x5A4D) return false; // MZ

    uint32_t pe_offset = *reinterpret_cast<uint32_t*>(&data[0x3C]);
    if (pe_offset + 6 > data.size()) return false;

    uint32_t pe_signature = *reinterpret_cast<uint32_t*>(&data[pe_offset]);
    if (pe_signature != 0x00004550) return false; // PE\0\0

    uint16_t machine = *reinterpret_cast<uint16_t*>(&data[pe_offset + 4]);
    uint16_t numberOfSections = *reinterpret_cast<uint16_t*>(&data[pe_offset + 6]);
    uint32_t timeDateStamp = *reinterpret_cast<uint32_t*>(&data[pe_offset + 8]);
    uint16_t sizeOfOptionalHeader = *reinterpret_cast<uint16_t*>(&data[pe_offset + 20]);
    uint16_t characteristics = *reinterpret_cast<uint16_t*>(&data[pe_offset + 22]);

    size_t opt_header_start = pe_offset + 24;
    if (opt_header_start + sizeOfOptionalHeader > data.size()) return false;

    uint16_t magic = *reinterpret_cast<uint16_t*>(&data[opt_header_start]);
    bool is64 = (magic == 0x20b);

    uint64_t imageBase = is64 ?
        *reinterpret_cast<uint64_t*>(&data[opt_header_start + 24]) :
        *reinterpret_cast<uint32_t*>(&data[opt_header_start + 28]);

    uint32_t entryPoint = *reinterpret_cast<uint32_t*>(&data[opt_header_start + 16]);
    uint32_t sectionAlignment = *reinterpret_cast<uint32_t*>(&data[opt_header_start + 32]);
    uint32_t fileAlignment = *reinterpret_cast<uint32_t*>(&data[opt_header_start + 36]);

    size_t section_table_offset = opt_header_start + sizeOfOptionalHeader;
    size_t section_size = 40;

    std::vector<SectionInfo> sections;
    for (int i = 0; i < numberOfSections; ++i) {
        size_t off = section_table_offset + i * section_size;
        if (off + section_size > data.size()) break;

        SectionInfo sec;
        sec.name = std::string(reinterpret_cast<char*>(&data[off]), 8);
        size_t null_pos = sec.name.find('\0');
        if (null_pos != std::string::npos)
            sec.name.erase(null_pos);

        sec.virtualSize = *reinterpret_cast<uint32_t*>(&data[off + 8]);
        sec.virtualAddress = *reinterpret_cast<uint32_t*>(&data[off + 12]);
        sec.rawDataSize = *reinterpret_cast<uint32_t*>(&data[off + 16]);
        sec.rawDataPtr = *reinterpret_cast<uint32_t*>(&data[off + 20]);

        sections.push_back(sec);
    }

    info = {
        machine,
        numberOfSections,
        timeDateStamp,
        sizeOfOptionalHeader,
        characteristics,
        is64,
        imageBase,
        entryPoint,
        sectionAlignment,
        fileAlignment,
        sections
    };

    return true;
}

void PEParser::clear() {
    data.clear();
    info = {};
}

bool parse_pe_headers(const std::string& file_path) {
    PEParser parser;
    if (!parser.load(file_path)) return false;
    peInfo = parser.get_info();
    return true;
}

void render_pe_headers_tab() {
    ImGui::Text("Machine: 0x%X", peInfo.machine);
    ImGui::Text("Number of Sections: %d", peInfo.numberOfSections);
    ImGui::Text("TimeDateStamp: 0x%X", peInfo.timeDateStamp);
    ImGui::Text("Characteristics: 0x%X", peInfo.characteristics);

    if (peInfo.is64) {
        ImGui::Text("ImageBase: 0x%llX", (unsigned long long)peInfo.imageBase);
    } else {
        ImGui::Text("ImageBase: 0x%X", (uint32_t)peInfo.imageBase);
    }

    ImGui::Text("Entry Point: 0x%X", peInfo.entryPoint);
    ImGui::Text("Section Alignment: 0x%X", peInfo.sectionAlignment);
    ImGui::Text("File Alignment: 0x%X", peInfo.fileAlignment);

    if (ImGui::TreeNode("Sections")) {
        for (const auto& sec : peInfo.sections) {
            ImGui::BulletText("Name: %s | VA: 0x%X | VS: 0x%X | RS: 0x%X | RPtr: 0x%X",
                sec.name.c_str(), sec.virtualAddress, sec.virtualSize, sec.rawDataSize, sec.rawDataPtr);
        }
        ImGui::TreePop();
    }
}
