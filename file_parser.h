#ifndef FILE_PARSER_H
#define FILE_PARSER_H

#include "imgui.h"
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <cstring>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <set>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <map>

// --- HASHING & DISASM LIBS ---
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <capstone/capstone.h>

// --- Data Structures (Generic) ---
struct SectionInfo {
    std::string name;
    uint64_t virtualAddress;
    uint64_t virtualSize;
    uint64_t rawDataPtr;
    uint64_t rawDataSize;
    double entropy = 0.0; 
};

struct ImportInfo {
    std::string dll_name;
    std::vector<std::string> function_names;
};

struct FileInfo {
    std::string type;
    std::string architecture;
    uint64_t entryPoint;
    uint64_t fileSize; 
    double fileEntropy; 
    std::string md5; 
    std::string sha1; 
    std::string sha256; 
    std::vector<SectionInfo> sections;
    std::vector<ImportInfo> imports;
    std::vector<std::string> strings;
    std::vector<std::string> disassembly;
};

// --- Base FileParser Interface ---
class FileParser {
public:
    virtual ~FileParser() = default;

    virtual bool parse(const std::vector<uint8_t>& data) {
        fileData = data;
        info.type = "Unknown (Strings only)";
        info.architecture = "N/A";
        info.entryPoint = 0;
        info.fileSize = fileData.size();
        
        calculateHashes();
        info.fileEntropy = calculateEntropy(fileData.data(), fileData.size());
        extractStrings();
        return true;
    }

    FileInfo getInfo() const { return info; }

protected:
    FileInfo info;
    std::vector<uint8_t> fileData;

    std::string bytesToHex(const unsigned char* bytes, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }

    void calculateHashes() {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        
        // Modern EVP API for MD5
        EVP_MD_CTX* md5_ctx = EVP_MD_CTX_new();
        if (md5_ctx) {
            EVP_DigestInit_ex(md5_ctx, EVP_md5(), NULL);
            EVP_DigestUpdate(md5_ctx, fileData.data(), fileData.size());
            EVP_DigestFinal_ex(md5_ctx, hash, NULL);
            EVP_MD_CTX_free(md5_ctx);
            info.md5 = bytesToHex(hash, MD5_DIGEST_LENGTH);
        }

        // Modern EVP API for SHA1
        EVP_MD_CTX* sha1_ctx = EVP_MD_CTX_new();
        if (sha1_ctx) {
            EVP_DigestInit_ex(sha1_ctx, EVP_sha1(), NULL);
            EVP_DigestUpdate(sha1_ctx, fileData.data(), fileData.size());
            EVP_DigestFinal_ex(sha1_ctx, hash, NULL);
            EVP_MD_CTX_free(sha1_ctx);
            info.sha1 = bytesToHex(hash, SHA_DIGEST_LENGTH);
        }

        // Modern EVP API for SHA256
        EVP_MD_CTX* sha256_ctx = EVP_MD_CTX_new();
        if (sha256_ctx) {
            EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(sha256_ctx, fileData.data(), fileData.size());
            EVP_DigestFinal_ex(sha256_ctx, hash, NULL);
            EVP_MD_CTX_free(sha256_ctx);
            info.sha256 = bytesToHex(hash, SHA256_DIGEST_LENGTH);
        }
    }

    double calculateEntropy(const uint8_t* data, size_t size) {
        if (size == 0) return 0.0;
        std::map<uint8_t, size_t> counts;
        for (size_t i = 0; i < size; ++i) {
            counts[data[i]]++;
        }

        double entropy = 0.0;
        for (auto const& [byte, count] : counts) {
            double probability = static_cast<double>(count) / size;
            if (probability > 0) {
                entropy -= probability * log2(probability);
            }
        }
        return entropy;
    }

    void extractStrings() {
        std::string current_string;
        std::set<std::string> found_strings;
        for (size_t i = 0; i < fileData.size(); ++i) {
            char c = fileData[i];
            if (isprint(c) || c == '\t') {
                current_string += c;
            } else {
                if (current_string.length() >= 5) {
                    found_strings.insert(current_string);
                }
                current_string.clear();
            }
        }
        if (current_string.length() >= 5) {
            found_strings.insert(current_string);
        }
        info.strings.assign(found_strings.begin(), found_strings.end());
    }

    void disassemble(bool is64, uint64_t entryPoint, uint64_t codeSectionAddr, uint64_t codeSectionPtr, size_t codeSectionSize) {
        csh handle;
        cs_arch arch = CS_ARCH_X86;
        cs_mode mode = is64 ? CS_MODE_64 : CS_MODE_32;
        if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
            info.disassembly.push_back("Failed to initialize Capstone");
            return;
        }
        cs_insn *insn;
        const uint8_t* code = &fileData[codeSectionPtr];
        size_t code_size = codeSectionSize;
        uint64_t entry_offset_in_section = 0;
        if (entryPoint > codeSectionAddr && entryPoint - codeSectionAddr < code_size) {
            entry_offset_in_section = entryPoint - codeSectionAddr;
        }

        if (entry_offset_in_section > code_size) {
            info.disassembly.push_back("Error: Entry point offset is outside the code section.");
            cs_close(&handle);
            return;
        }

        const uint8_t* entry_code = code + entry_offset_in_section;
        size_t entry_code_size = code_size - entry_offset_in_section;
        uint64_t runtime_address = entryPoint;
        size_t count = cs_disasm(handle, entry_code, entry_code_size, runtime_address, 100, &insn);
        if (count > 0) {
            for (size_t i = 0; i < count; i++) {
                std::stringstream ss;
                ss << "0x" << std::hex << insn[i].address << ":\t" << insn[i].mnemonic << "\t" << insn[i].op_str;
                info.disassembly.push_back(ss.str());
            }
            cs_free(insn, count);
        } else {
            info.disassembly.push_back("Failed to disassemble code at entry point.");
        }
        cs_close(&handle);
    }
};

// --- PE Parser (for Windows) ---
class PEParser : public FileParser {
public:
    bool parse(const std::vector<uint8_t>& data) override {
        fileData = data;
        info = {};
        if (fileData.size() < 0x100) return false;
        if (*reinterpret_cast<const uint16_t*>(&fileData[0]) != 0x5A4D) return false;
        uint32_t pe_offset = *reinterpret_cast<const uint32_t*>(&fileData[0x3C]);
        if (pe_offset + 24 + sizeof(uint16_t) > fileData.size()) return false;
        if (*reinterpret_cast<const uint32_t*>(&fileData[pe_offset]) != 0x00004550) return false;
        info.type = "PE (Windows)";
        info.fileSize = fileData.size();
        uint16_t machine = *reinterpret_cast<const uint16_t*>(&fileData[pe_offset + 4]);
        uint16_t numberOfSections = *reinterpret_cast<const uint16_t*>(&fileData[pe_offset + 6]);
        uint16_t sizeOfOptionalHeader = *reinterpret_cast<const uint16_t*>(&fileData[pe_offset + 20]);
        size_t opt_header_start = pe_offset + 24;
        if (opt_header_start + sizeOfOptionalHeader > fileData.size()) return false;
        uint16_t magic = *reinterpret_cast<const uint16_t*>(&fileData[opt_header_start]);
        bool is64 = (magic == 0x20b);
        info.architecture = (machine == 0x8664 || is64) ? "64-bit" : "32-bit";
        info.entryPoint = *reinterpret_cast<const uint32_t*>(&fileData[opt_header_start + 16]);
        SectionInfo codeSection = {};
        for (int i = 0; i < numberOfSections; ++i) {
            size_t off = opt_header_start + sizeOfOptionalHeader + i * 40;
            if (off + 40 > fileData.size()) break;
            SectionInfo sec;
            sec.name = std::string(reinterpret_cast<const char*>(&fileData[off]), 8);
            sec.name.erase(sec.name.find('\0'));
            sec.virtualSize = *reinterpret_cast<const uint32_t*>(&fileData[off + 8]);
            sec.virtualAddress = *reinterpret_cast<const uint32_t*>(&fileData[off + 12]);
            sec.rawDataSize = *reinterpret_cast<const uint32_t*>(&fileData[off + 16]);
            sec.rawDataPtr = *reinterpret_cast<const uint32_t*>(&fileData[off + 20]);
            if (sec.rawDataPtr > 0 && sec.rawDataSize > 0 && (sec.rawDataPtr + sec.rawDataSize <= fileData.size())) {
                sec.entropy = calculateEntropy(&fileData[sec.rawDataPtr], sec.rawDataSize);
            }
            info.sections.push_back(sec);
            if (sec.name == ".text") codeSection = sec;
        }
        calculateHashes();
        info.fileEntropy = calculateEntropy(fileData.data(), fileData.size());
        parse_imports(opt_header_start, is64);
        extractStrings();
        if (codeSection.rawDataSize > 0 && codeSection.rawDataPtr + codeSection.rawDataSize <= fileData.size()) {
            disassemble(is64, info.entryPoint, codeSection.virtualAddress, codeSection.rawDataPtr, codeSection.rawDataSize);
        } else {
            info.disassembly.push_back("Could not find .text section to disassemble.");
        }
        return true;
    }

private:
    uint32_t RvaToOffset(uint32_t rva) {
        for (const auto& sec : info.sections) {
            if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
                return (rva - sec.virtualAddress) + sec.rawDataPtr;
            }
        }
        return 0;
    }
    
    void parse_imports(size_t opt_header_start, bool is64) {
        uint32_t import_dir_rva = 0;
        if (is64) {
            if (opt_header_start + 112 + 8 > fileData.size()) return;
            import_dir_rva = *reinterpret_cast<const uint32_t*>(&fileData[opt_header_start + 112]);
        } else {
            if (opt_header_start + 96 + 8 > fileData.size()) return;
            import_dir_rva = *reinterpret_cast<const uint32_t*>(&fileData[opt_header_start + 96]);
        }
        if (import_dir_rva == 0) return;
        uint32_t import_offset = RvaToOffset(import_dir_rva);
        if (import_offset == 0) return;
        for (size_t i = 0; ; ++i) {
            size_t desc_offset = import_offset + i * 20;
            if (desc_offset + 20 > fileData.size()) break;
            uint32_t name_rva = *reinterpret_cast<const uint32_t*>(&fileData[desc_offset + 12]);
            if (name_rva == 0) break;
            uint32_t oft_rva = *reinterpret_cast<const uint32_t*>(&fileData[desc_offset + 0]);
            uint32_t ft_rva = *reinterpret_cast<const uint32_t*>(&fileData[desc_offset + 16]);
            uint32_t name_offset = RvaToOffset(name_rva);
            if (name_offset == 0 || name_offset >= fileData.size()) continue;
            ImportInfo import_info;
            import_info.dll_name = std::string(reinterpret_cast<const char*>(&fileData[name_offset]));
            uint32_t thunk_rva = (oft_rva != 0) ? oft_rva : ft_rva;
            uint32_t thunk_offset = RvaToOffset(thunk_rva);
            if (thunk_offset == 0) continue;
            size_t thunk_size = is64 ? 8 : 4;
            for (int j = 0; ; ++j) {
                size_t entry_offset = thunk_offset + j * thunk_size;
                if (entry_offset + thunk_size > fileData.size()) break;
                uint64_t thunk_data = is64 ?
                    *reinterpret_cast<const uint64_t*>(&fileData[entry_offset]) :
                    *reinterpret_cast<const uint32_t*>(&fileData[entry_offset]);
                if (thunk_data == 0) break;
                if (thunk_data & (is64 ? 0x8000000000000000 : 0x80000000)) {
                    import_info.function_names.push_back("Ordinal: " + std::to_string(thunk_data & 0xFFFF));
                } else {
                    uint32_t name_hint_offset = RvaToOffset(thunk_data);
                    if (name_hint_offset != 0 && name_hint_offset + 2 < fileData.size()) {
                        import_info.function_names.push_back(std::string(reinterpret_cast<const char*>(&fileData[name_hint_offset + 2])));
                    }
                }
            }
            if (!import_info.function_names.empty()) info.imports.push_back(import_info);
        }
    }
};

// --- ELF Parser (for Linux) ---
class ELFParser : public FileParser {
    struct Elf64_Ehdr {
        unsigned char e_ident[16];
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_version;
        uint64_t e_entry;
        uint64_t e_phoff;
        uint64_t e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize;
        uint16_t e_phentsize;
        uint16_t e_phnum;
        uint16_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
    };
     struct Elf64_Shdr {
        uint32_t sh_name;
        uint32_t sh_type;
        uint64_t sh_flags;
        uint64_t sh_addr;
        uint64_t sh_offset;
        uint64_t sh_size;
        uint32_t sh_link;
        uint32_t sh_info;
        uint64_t sh_addralign;
        uint64_t sh_entsize;
    };
public:
    bool parse(const std::vector<uint8_t>& data) override {
        fileData = data;
        info = {};
        if (fileData.size() < 64) return false; 
        
        auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(fileData.data());
        if (memcmp(ehdr->e_ident, "\x7F" "ELF", 4) != 0) return false;

        info.type = "ELF (Linux)";
        info.fileSize = fileData.size();
        bool is64 = ehdr->e_ident[4] == 2; 
        
        SectionInfo codeSection = {};
        if (is64) {
            info.architecture = "64-bit";
            info.entryPoint = ehdr->e_entry;
            uint64_t shoff = ehdr->e_shoff;
            uint16_t shentsize = ehdr->e_shentsize;
            uint16_t shnum = ehdr->e_shnum;
            uint16_t shstrndx = ehdr->e_shstrndx;

            if (shstrndx > 0 && shstrndx < shnum && (shoff + shnum * shentsize <= fileData.size())) {
                 auto* sh_strtab_hdr = reinterpret_cast<const Elf64_Shdr*>(&fileData[shoff + shstrndx * shentsize]);
                 if (sh_strtab_hdr->sh_offset + sh_strtab_hdr->sh_size <= fileData.size()) {
                    const char* sh_strtab = reinterpret_cast<const char*>(&fileData[sh_strtab_hdr->sh_offset]);
                    for (int i = 0; i < shnum; ++i) {
                        auto* shdr = reinterpret_cast<const Elf64_Shdr*>(&fileData[shoff + i * shentsize]);
                        SectionInfo sec;
                        sec.name = &sh_strtab[shdr->sh_name];
                        sec.virtualAddress = shdr->sh_addr;
                        sec.virtualSize = shdr->sh_size;
                        sec.rawDataPtr = shdr->sh_offset;
                        sec.rawDataSize = shdr->sh_size;
                        
                        if (sec.rawDataPtr > 0 && sec.rawDataSize > 0 && (sec.rawDataPtr + sec.rawDataSize <= fileData.size())) {
                            sec.entropy = calculateEntropy(&fileData[sec.rawDataPtr], sec.rawDataSize);
                        }
                        
                        info.sections.push_back(sec);
                        if (sec.name == ".text") codeSection = sec;
                    }
                 }
            }
        } else {
            info.architecture = "32-bit";
            info.entryPoint = *reinterpret_cast<const uint32_t*>(&fileData[24]);
        }

        calculateHashes();
        info.fileEntropy = calculateEntropy(fileData.data(), fileData.size());
        extractStrings();

        if (is64 && codeSection.rawDataSize > 0 && codeSection.rawDataPtr + codeSection.rawDataSize <= fileData.size()) {
            disassemble(is64, info.entryPoint, codeSection.virtualAddress, codeSection.rawDataPtr, codeSection.rawDataSize);
        } else if (!is64) {
            info.disassembly.push_back("32-bit ELF disassembly not implemented.");
        } else {
            info.disassembly.push_back("Could not find .text section to disassemble.");
        }
        return true;
    }
};

// --- Factory Function ---
static std::unique_ptr<FileParser> create_parser(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return nullptr;
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size < 64) {
        if(size > 0) { 
             std::vector<uint8_t> data(size);
             file.read(reinterpret_cast<char*>(data.data()), size);
             auto parser = std::make_unique<FileParser>();
             if(parser->parse(data)) return parser;
        }
        return nullptr;
    }
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    if (data.size() > 0x40 && *reinterpret_cast<const uint16_t*>(&data[0]) == 0x5A4D) {
        uint32_t pe_offset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
        if (pe_offset + 4 < data.size() && memcmp(&data[pe_offset], "PE\0\0", 4) == 0) {
            auto parser = std::make_unique<PEParser>();
            if (parser->parse(data)) return parser;
        }
    }
    if (memcmp(data.data(), "\x7F" "ELF", 4) == 0) {
        auto parser = std::make_unique<ELFParser>();
        if (parser->parse(data)) return parser;
    }
    auto parser = std::make_unique<FileParser>();
    if(parser->parse(data)) return parser;
    return nullptr; 
}

#endif // FILE_PARSER_H