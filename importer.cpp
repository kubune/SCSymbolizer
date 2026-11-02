
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace MachO {

constexpr uint32_t MAGIC = 0xFEEDFACF;
constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_SYMTAB = 0x02;
constexpr uint32_t LC_DYSYMTAB = 0x0B;
constexpr uint32_t LC_CODE_SIGNATURE = 0x1D;

constexpr uint32_t MH_EXECUTE = 0x02;
constexpr uint8_t N_SECT = 0x0E;

constexpr size_t HEADER_SIZE = 32;
constexpr size_t SEGMENT_COMMAND_SIZE = 72;
constexpr size_t SECTION_SIZE = 80;
constexpr size_t NLIST_SIZE = 16;

struct Section {
    uint64_t start;
    uint64_t end;
    uint8_t globalIndex;
};

struct Segment {
    std::string name;
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    size_t commandOffset;
};

struct Symbol {
    uint64_t address;
    std::string name;
};

struct Symtab {
    size_t commandOffset;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct Dysymtab {
    size_t commandOffset;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
};

struct CodeSignature {
    size_t commandOffset;
    uint32_t dataoff;
    uint32_t datasize;
};

uint32_t read32(const std::vector<uint8_t>& data, size_t offset) {
    if (offset > data.size() || data.size() - offset < 4) throw std::runtime_error("Unexpected end of file");

    return static_cast<uint32_t>(data[offset]) |
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) |
           (static_cast<uint32_t>(data[offset + 3]) << 24);
}

uint64_t read64(const std::vector<uint8_t>& data, size_t offset) {
    if (offset > data.size() || data.size() - offset < 8) throw std::runtime_error("Unexpected end of file");
    return static_cast<uint64_t>(read32(data, offset)) | (static_cast<uint64_t>(read32(data, offset + 4)) << 32);
}

void write32(std::vector<uint8_t>& data, size_t offset, uint32_t value) {
    if (offset > data.size() || data.size() - offset < 4) throw std::runtime_error("Invalid write offset");
    for (int i = 0; i < 4; ++i) data[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

void write64(std::vector<uint8_t>& data, size_t offset, uint64_t value) {
    if (offset > data.size() || data.size() - offset < 8) throw std::runtime_error("Invalid write offset");

    write32(data, offset, static_cast<uint32_t>(value));
    write32(data, offset + 4, static_cast<uint32_t>(value >> 32));
}

void append32(std::vector<uint8_t>& data, uint32_t value) {
    for (int i = 0; i < 4; ++i) data.push_back(static_cast<uint8_t>(value >> (i * 8)));
}

void append64(std::vector<uint8_t>& data, uint64_t value) {
    append32(data, static_cast<uint32_t>(value));
    append32(data, static_cast<uint32_t>(value >> 32));
}

std::string readName(const std::vector<uint8_t>& data, size_t offset, size_t length) {
    if (offset > data.size() || data.size() - offset < length) throw std::runtime_error("Invalid name offset");

    size_t end = offset;
    while (end < offset + length && data[end] != 0) ++end;

    return std::string(reinterpret_cast<const char*>(data.data() + offset), end - offset);
}

std::vector<Symbol> parseSymbols(const std::string& path) {
    std::ifstream file(path);

    if (!file) throw std::runtime_error("Cannot open symbol file: " + path);

    std::vector<Symbol> symbols;
    std::string line;

    while (std::getline(file, line)) {
        size_t pos = line.find_first_not_of(" \t\r\n");

        if (pos == std::string::npos) continue;

        line.erase(0, pos);

        size_t separator = line.find_first_of(" \t");

        if (separator == std::string::npos) continue;

        std::string addressText = line.substr(0, separator);
        std::string name = line.substr(separator);

        size_t nameStart = name.find_first_not_of(" \t");

        if (nameStart == std::string::npos) continue;

        name.erase(0, nameStart);

        try {
            size_t consumed = 0;
            uint64_t address = std::stoull(addressText, &consumed, 16);
            if (consumed != addressText.size()) continue;
            symbols.push_back({address, name});
        }
        catch (...) {
            continue;
        }
    }

    return symbols;
}

void appendNlist(std::vector<uint8_t>& output, uint32_t stringIndex, uint8_t sectionIndex, uint64_t address) {
    append32(output, stringIndex);

    output.push_back(N_SECT);
    output.push_back(sectionIndex);

    output.push_back(0);
    output.push_back(0);

    append64(output, address);
}

void process(const std::string& inputPath, const std::string& symbolPath, const std::string& outputPath) {
    std::ifstream input(inputPath, std::ios::binary);

    if (!input) throw std::runtime_error("Cannot open input executable");

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());

    if (data.size() < HEADER_SIZE) throw std::runtime_error("File is too small");
    if (read32(data, 0) != MAGIC) throw std::runtime_error("Not a little-endian 64-bit Mach-O file");
    if (read32(data, 12) != MH_EXECUTE) throw std::runtime_error("Expected a Mach-O executable");

    uint32_t ncmds = read32(data, 16);
    uint32_t sizeofcmds = read32(data, 20);

    if (sizeofcmds > data.size() - HEADER_SIZE)
        throw std::runtime_error("Invalid load command size");

    std::vector<Segment> segments;
    std::vector<Section> sections;

    Symtab symtab{};
    Dysymtab dysymtab{};
    CodeSignature signature{};

    bool hasSymtab = false;
    bool hasDysymtab = false;
    bool hasSignature = false;

    size_t offset = HEADER_SIZE;
    uint32_t globalSectionIndex = 0;

    for (uint32_t i = 0; i < ncmds; ++i) {
        uint32_t cmd = read32(data, offset);
        uint32_t cmdsize = read32(data, offset + 4);

        if (cmdsize < 8 ||
            cmdsize > data.size() - offset ||
            cmdsize > HEADER_SIZE + sizeofcmds - offset) {
            throw std::runtime_error("Invalid load command");
        }

        if (cmd == LC_SEGMENT_64) {
            if (cmdsize < SEGMENT_COMMAND_SIZE) {
                throw std::runtime_error("Invalid segment command");
            }

            Segment segment{};

            segment.name = readName(data, offset + 8, 16);
            segment.vmaddr = read64(data, offset + 24);
            segment.vmsize = read64(data, offset + 32);
            segment.fileoff = read64(data, offset + 40);
            segment.filesize = read64(data, offset + 48);
            segment.commandOffset = offset;

            uint32_t nsects = read32(data, offset + 64);

            if (nsects > (cmdsize - SEGMENT_COMMAND_SIZE) / SECTION_SIZE) {
                throw std::runtime_error("Invalid section count");
            }

            size_t sectionOffset = offset + SEGMENT_COMMAND_SIZE;

            for (uint32_t j = 0; j < nsects; ++j) {
                ++globalSectionIndex;

                uint64_t addr = read64(data, sectionOffset + 32);
                uint64_t size = read64(data, sectionOffset + 40);

                if (size > UINT64_MAX - addr) {
                    throw std::runtime_error("Section address overflow");
                }

                if (globalSectionIndex > 255) {
                    throw std::runtime_error("Too many Mach-O sections");
                }

                sections.push_back({ addr, addr + size, static_cast<uint8_t>(globalSectionIndex) });

                sectionOffset += SECTION_SIZE;
            }

            segments.push_back(segment);
        }
        else if (cmd == LC_SYMTAB) {
            if (cmdsize < 24) {
                throw std::runtime_error("Invalid LC_SYMTAB");
            }

            symtab = {
                offset,
                read32(data, offset + 8),
                read32(data, offset + 12),
                read32(data, offset + 16),
                read32(data, offset + 20)
            };

            hasSymtab = true;
        }
        else if (cmd == LC_DYSYMTAB) {
            if (cmdsize < 80) {
                throw std::runtime_error("Invalid LC_DYSYMTAB");
            }

            dysymtab = {
                offset,
                read32(data, offset + 8),
                read32(data, offset + 12),
                read32(data, offset + 16),
                read32(data, offset + 20),
                read32(data, offset + 24),
                read32(data, offset + 28)
            };

            hasDysymtab = true;
        }
        else if (cmd == LC_CODE_SIGNATURE) {
            if (cmdsize < 16) {
                throw std::runtime_error("Invalid code signature command");
            }

            signature = { offset, read32(data, offset + 8), read32(data, offset + 12) };

            hasSignature = true;
        }

        offset += cmdsize;
    }

    if (!hasSymtab || !hasDysymtab) {
        throw std::runtime_error("Missing symbol table commands");
    }

    if (!hasSignature) {
        throw std::runtime_error("Missing LC_CODE_SIGNATURE");
    }
    auto linkedit = std::find_if(segments.begin(), segments.end(),
        [](const Segment& s) {
            return s.name == "__LINKEDIT";
        }
    );

    if (linkedit == segments.end()) {
        throw std::runtime_error("__LINKEDIT not found");
    }

    if (linkedit->fileoff > data.size() ||
        linkedit->filesize > data.size() - linkedit->fileoff) {
            throw std::runtime_error("Invalid __LINKEDIT range");
    }

    if (linkedit->fileoff + linkedit->filesize != data.size()) {
        throw std::runtime_error("__LINKEDIT must extend to the end of the file");
    }

    uint64_t imageBase = UINT64_MAX;
    for (const auto& segment : segments) {
        if (segment.name != "__PAGEZERO") {
            imageBase = std::min(imageBase, segment.vmaddr);
        }
    }

    if (imageBase == UINT64_MAX) {
        throw std::runtime_error("Cannot determine image base");
    }

    std::vector<Symbol> symbols = parseSymbols(symbolPath);
    if (symbols.empty()) {
        throw std::runtime_error("No symbols parsed");
    }
    uint64_t oldSymbolSize = static_cast<uint64_t>(symtab.nsyms) * NLIST_SIZE;

    if (symtab.symoff > data.size() || oldSymbolSize > data.size() - symtab.symoff) {
        throw std::runtime_error("Existing symbol table is truncated");
    }

    if (symtab.stroff > data.size() || symtab.strsize > data.size() - symtab.stroff) {
        throw std::runtime_error("Existing string table is truncated");
    }

    if (symtab.strsize == 0 || data[symtab.stroff] != 0) {
        throw std::runtime_error("Malformed string table");
    }

    if (dysymtab.ilocalsym > symtab.nsyms ||
        dysymtab.nlocalsym > symtab.nsyms - dysymtab.ilocalsym) {
            throw std::runtime_error("Invalid local symbol range");
    }

    if (dysymtab.iextdefsym > symtab.nsyms ||
        dysymtab.nextdefsym > symtab.nsyms - dysymtab.iextdefsym ||
        dysymtab.iundefsym > symtab.nsyms ||
        dysymtab.nundefsym > symtab.nsyms - dysymtab.iundefsym) {
            throw std::runtime_error("Invalid dynamic symbol ranges");
    }

    std::vector<uint8_t> oldSymbols(data.begin() + symtab.symoff, data.begin() + symtab.symoff + oldSymbolSize);
    std::vector<uint8_t> oldStrings(data.begin() + symtab.stroff, data.begin() + symtab.stroff + symtab.strsize);
    std::vector<uint8_t> newEntries;
    std::vector<uint8_t> newStrings;
    uint32_t added = 0;
    uint32_t skipped = 0;

    for (const auto& symbol : symbols) {
        if (symbol.address > UINT64_MAX - imageBase) {
            ++skipped;
            continue;
        }

        uint64_t vmAddress = imageBase + symbol.address;

        auto section = std::find_if(sections.begin(), sections.end(),
            [vmAddress](const Section& s) {
                return vmAddress >= s.start && vmAddress < s.end;
            }
        );

        if (section == sections.end()) {
            std::cout << "Skipping address 0x" << std::hex << symbol.address << std::dec << ": not inside section" << std::endl;

            ++skipped;
            continue;
        }

        std::string name = symbol.name;

        if (name.empty()) {
            ++skipped;
            continue;
        }

        if (name.front() != '_') {
            name.insert(name.begin(), '_');
        }

        if (name.find('\0') != std::string::npos) {
            ++skipped;
            continue;
        }

        uint64_t stringIndex64 = static_cast<uint64_t>(oldStrings.size()) + newStrings.size();

        if (stringIndex64 > UINT32_MAX) {
            throw std::runtime_error("String table is too large");
        }

        uint32_t stringIndex =static_cast<uint32_t>(stringIndex64);

        for (unsigned char c : name) {
            newStrings.push_back(c);
        }

        newStrings.push_back(0);
        appendNlist(newEntries, stringIndex, section->globalIndex, vmAddress);
        ++added;
    }

    if (added == 0)
    {
        throw std::runtime_error("No symbols could be added");
    }

    size_t localInsertion = static_cast<size_t>(dysymtab.ilocalsym + dysymtab.nlocalsym) * NLIST_SIZE;

    std::vector<uint8_t> combinedSymbols;

    combinedSymbols.reserve(oldSymbols.size() + newEntries.size());
    combinedSymbols.insert(combinedSymbols.end(), oldSymbols.begin(), oldSymbols.begin() + localInsertion);
    combinedSymbols.insert(combinedSymbols.end(), newEntries.begin(), newEntries.end());
    combinedSymbols.insert(combinedSymbols.end(), oldSymbols.begin() + localInsertion, oldSymbols.end());

    std::vector<uint8_t> combinedStrings = oldStrings;
    combinedStrings.insert(combinedStrings.end(), newStrings.begin(), newStrings.end());

    if (symtab.nsyms > UINT32_MAX - added)
    {
        throw std::runtime_error("Too many symbols");
    }

    if (combinedStrings.size() > UINT32_MAX)
    {
        throw std::runtime_error("String table exceeds Mach-O limits");
    }

    uint64_t newSymoff64 = data.size();
    uint64_t newStroff64 = newSymoff64 + combinedSymbols.size();
    uint64_t newEnd64 = newStroff64 + combinedStrings.size();

    if (newEnd64 > UINT32_MAX)
    {
        throw std::runtime_error("Mach-O file offsets exceed 32-bit limits");
    }

    if (newEnd64 > SIZE_MAX) {
        throw std::runtime_error("Output file is too large");
    }

    uint64_t addedSize = newEnd64 - data.size();

    if (linkedit->vmsize > UINT64_MAX - addedSize || linkedit->filesize > UINT64_MAX - addedSize) {
        throw std::runtime_error("__LINKEDIT size overflow");
    }

    data.insert(data.end(), combinedSymbols.begin(), combinedSymbols.end());
    data.insert(data.end(), combinedStrings.begin(), combinedStrings.end());
    write32(data, symtab.commandOffset + 8, static_cast<uint32_t>(newSymoff64));
    write32(data, symtab.commandOffset + 12, symtab.nsyms + added);
    write32(data, symtab.commandOffset + 16, static_cast<uint32_t>(newStroff64));
    write32(data, symtab.commandOffset + 20, static_cast<uint32_t>(combinedStrings.size()));
    write32(data, dysymtab.commandOffset + 12, dysymtab.nlocalsym + added);

    if (dysymtab.iextdefsym >= dysymtab.ilocalsym + dysymtab.nlocalsym) {
        write32(data, dysymtab.commandOffset + 16, dysymtab.iextdefsym + added);
    }

    if (dysymtab.iundefsym >= dysymtab.ilocalsym + dysymtab.nlocalsym) {
        write32(data, dysymtab.commandOffset + 24, dysymtab.iundefsym + added);
    }

    write64(data, linkedit->commandOffset + 32, linkedit->vmsize + addedSize);
    write64(data, linkedit->commandOffset + 48, linkedit->filesize + addedSize);

    std::ofstream output(outputPath, std::ios::binary | std::ios::trunc);

    if (!output) {
        throw std::runtime_error("Cannot create output file");
    }

    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));

    if (!output)
        throw std::runtime_error("Failed writing output file");

    std::cout << "Imported: " << added << " symbols to " << outputPath << std::endl << std::endl;
    if (skipped > 0) std::cout << "Skipped: " << skipped << " symbols" << std::endl;

    std::cout
        << "NOTE: The original code signature is no longer valid." << std::endl
        << "This output is intended for static analysis.";
}

}