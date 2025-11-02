#ifndef PE_HEADERS_H
#define PE_HEADERS_H

#include <string>
#include <vector>
#include <cstdint>

struct SectionInfo {
    std::string name;
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t rawDataSize;
    uint32_t rawDataPtr;
};

// NEW: Structure to hold import data
struct ImportInfo {
    std::string dll_name;
    std::vector<std::string> function_names;
};

struct PEHeadersInfo {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
    bool is64;
    uint64_t imageBase;
    uint32_t entryPoint;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    std::vector<SectionInfo> sections;
    std::vector<ImportInfo> imports; // <-- ADDED
};

class PEParser {
public:
    bool load(const std::string& path);
    PEHeadersInfo get_info() const { return info; }

private:
    std::vector<uint8_t> data;
    PEHeadersInfo info;
    bool parse();
    bool parse_imports(); // <-- ADDED
    uint32_t RvaToOffset(uint32_t rva); // <-- ADDED
    void clear();
};

// Extern global object used in main.cpp
extern PEHeadersInfo peInfo;

// Functions matching your main.cpp references
bool parse_pe_headers(const std::string& file_path);  // used in menu bar
void render_pe_headers_tab();                         // used in PE tab
void render_pe_imports_tab();                         // <-- ADDED

#endif // PE_HEADERS_H
