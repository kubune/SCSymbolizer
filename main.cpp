#if defined(_WIN32) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#endif

#include "ByteStream.h"
#include "importer.h"

namespace {

#ifdef _WIN32
using PathString = std::wstring;
using ActionString = std::wstring;
const wchar_t *const kOutputSuffix = L"_symbols.txt";
const wchar_t *const kExportAction = L"export";
const wchar_t *const kImportAction = L"import";
#else
using PathString = std::string;
using ActionString = std::string;
const char *const kOutputSuffix = "_symbols.txt";
const char *const kExportAction = "export";
const char *const kImportAction = "import";
#endif

using Magic = std::array<std::uint8_t, 4>;

const Magic MH_MAGIC_64 = {{0xCF, 0xFA, 0xED, 0xFE}};
const Magic MH_CIGAM_64 = {{0xFE, 0xED, 0xFA, 0xCF}};
const Magic MH_MAGIC = {{0xCE, 0xFA, 0xED, 0xFE}};
const Magic MH_CIGAM = {{0xFE, 0xED, 0xFA, 0xCE}};

constexpr std::uint32_t LC_REQ_DYLD = 0x80000000u;
constexpr std::uint32_t LC_DYLD_INFO_ONLY = 0x22u | LC_REQ_DYLD;

constexpr std::uint64_t EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08;
constexpr std::uint64_t EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10;

struct Child {
	std::string suffix;
	std::uint64_t offset = 0;
};

struct Node {
	std::uint64_t offset = 0;
	bool hasAddress = false;
	std::uint64_t address = 0;
	std::vector<Child> children;
};

std::string displayPath(const PathString &path) {
#ifdef _WIN32
	if (path.empty()) {
		return std::string();
	}
	const int length = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), static_cast<int>(path.size()), nullptr, 0, nullptr, nullptr);
	if (length <= 0) {
		return std::string("<path>");
	}
	std::string result(static_cast<std::size_t>(length), '\0');
	WideCharToMultiByte(CP_UTF8, 0, path.c_str(), static_cast<int>(path.size()), &result[0], length, nullptr, nullptr);
	return result;
#else
	return path;
#endif
}

std::FILE *openFile(const PathString &path, bool forWriting) {
#ifdef _WIN32
	return _wfopen(path.c_str(), forWriting ? L"w" : L"rb");
#else
	return std::fopen(path.c_str(), forWriting ? "w" : "rb");
#endif
}

struct FileCloser {
	void operator()(std::FILE *file) const {
		if (file != nullptr) {
			std::fclose(file);
		}
	}
};
using FilePtr = std::unique_ptr<std::FILE, FileCloser>;

std::vector<std::uint8_t> readWholeFile(const PathString &path) {
	FilePtr file(openFile(path, false));
	if (!file) {
		throw std::runtime_error("Cannot open file for reading: " + displayPath(path));
	}
	std::vector<std::uint8_t> data;
	std::vector<std::uint8_t> chunk(1 << 16);
	while (true) {
		const std::size_t count = std::fread(chunk.data(), 1, chunk.size(), file.get());
		data.insert(data.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(count));
		if (count < chunk.size()) {
			break;
		}
	}
	if (std::ferror(file.get())) {
		throw std::runtime_error("Failed to read file: " + displayPath(path));
	}
	return data;
}

void writeWholeFile(const PathString &path, const std::string &content) {
	std::FILE *raw = openFile(path, true);
	if (raw == nullptr) {
		throw std::runtime_error("Cannot open file for writing: " + displayPath(path));
	}
	FilePtr file(raw);
	const bool written = content.empty() || std::fwrite(content.data(), 1, content.size(), file.get()) == content.size();
	if (std::fclose(file.release()) != 0 || !written) {
		throw std::runtime_error("Failed to write file: " + displayPath(path));
	}
}

std::uint64_t checkedAdd(std::uint64_t a, std::uint64_t b) {
	if (b > std::numeric_limits<std::uint64_t>::max() - a) {
		throw std::runtime_error("Offset overflow");
	}
	return a + b;
}

bool isValidUtf8(const std::string &text) {
	const std::size_t length = text.size();
	std::size_t i = 0;
	while (i < length) {
		const unsigned char lead = static_cast<unsigned char>(text[i]);
		if (lead < 0x80) {
			++i;
			continue;
		}
		std::size_t sequenceLength;
		std::uint32_t codePoint;
		if (lead >= 0xC2 && lead <= 0xDF) {
			sequenceLength = 2;
			codePoint = lead & 0x1Fu;
		} else if ((lead & 0xF0u) == 0xE0u) {
			sequenceLength = 3;
			codePoint = lead & 0x0Fu;
		} else if (lead >= 0xF0 && lead <= 0xF4) {
			sequenceLength = 4;
			codePoint = lead & 0x07u;
		} else {
			return false;
		}
		if (length - i < sequenceLength) {
			return false;
		}
		for (std::size_t k = 1; k < sequenceLength; ++k) {
			const unsigned char continuation = static_cast<unsigned char>(text[i + k]);
			if ((continuation & 0xC0u) != 0x80u) {
				return false;
			}
			codePoint = (codePoint << 6) | (continuation & 0x3Fu);
		}
		if (sequenceLength == 3 && (codePoint < 0x800 || (codePoint >= 0xD800 && codePoint <= 0xDFFF))) {
			return false;
		}
		if (sequenceLength == 4 && (codePoint < 0x10000 || codePoint > 0x10FFFF)) {
			return false;
		}
		i += sequenceLength;
	}
	return true;
}

std::string toHex(std::uint64_t value) {
	static const char digits[] = "0123456789abcdef";
	if (value == 0) {
		return "0";
	}
	std::string reversed;
	while (value != 0) {
		reversed.push_back(digits[value & 0xF]);
		value >>= 4;
	}
	return std::string(reversed.rbegin(), reversed.rend());
}

std::size_t extractSymbols(const PathString &fileName) {
	ByteStream stream(readWholeFile(fileName));

	const std::uint8_t *magicBytes = stream.readBytes(4);
	Magic magic;
	std::memcpy(magic.data(), magicBytes, magic.size());

	const bool is64Bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
	if (magic == MH_CIGAM_64 || magic == MH_CIGAM) {
		stream.endian = ByteStream::Endian::Big;
	} else if (magic != MH_MAGIC_64 && magic != MH_MAGIC) {
		throw std::runtime_error("Only 32-bit and 64-bit Mach-O files are supported");
	}

	stream.offset += 3 * 4;
	const std::uint32_t ncmds = stream.readUInt32();
	stream.offset += is64Bit ? 3 * 4 : 2 * 4;

	bool foundDyldInfo = false;
	std::uint64_t exportOffset = 0;
	std::uint64_t exportEndOffset = 0;
	for (std::uint32_t i = 0; i < ncmds; ++i) {
		const std::uint64_t commandOffset = stream.offset;
		const std::uint32_t cmd = stream.readUInt32();
		const std::uint32_t cmdsize = stream.readUInt32();
		if (cmd == LC_DYLD_INFO_ONLY) {
			stream.offset += 8 * 4;
			exportOffset = stream.readUInt32();
			const std::uint64_t exportSize = stream.readUInt32();
			exportEndOffset = exportOffset + exportSize;
			foundDyldInfo = true;
			break;
		}
		stream.offset = commandOffset + cmdsize;
	}
	if (!foundDyldInfo) {
		throw std::runtime_error("Command LC_DYLD_INFO_ONLY is missing");
	}

	std::vector<Node> nodes;
	stream.offset = exportOffset;
	while (stream.offset < exportEndOffset) {
		Node node;
		node.offset = stream.offset;

		const std::uint64_t terminalSize = stream.readULEB128();
		const std::uint64_t terminalEndOffset = checkedAdd(terminalSize, stream.offset);
		if (terminalEndOffset > stream.offset) {
			const std::uint64_t flags = stream.readULEB128();
			if (!(flags & (EXPORT_SYMBOL_FLAGS_REEXPORT | EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER))) {
				node.address = stream.readULEB128();
				node.hasAddress = true;
			}
		}
		stream.offset = terminalEndOffset;

		const unsigned childCount = stream.readUInt8();
		for (unsigned i = 0; i < childCount; ++i) {
			Child child;
			std::string suffix = stream.readCString();
			child.suffix = isValidUtf8(suffix) ? std::move(suffix) : std::string("ERROR");
			child.offset = checkedAdd(exportOffset, stream.readULEB128());
			node.children.push_back(std::move(child));
		}
		nodes.push_back(std::move(node));
	}

	std::unordered_map<std::uint64_t, std::size_t> nodeOffsetToNode;
	std::unordered_set<std::uint64_t> childOffsets;
	for (std::size_t i = 0; i < nodes.size(); ++i) {
		nodeOffsetToNode[nodes[i].offset] = i;
		for (const Child &child : nodes[i].children) {
			childOffsets.insert(child.offset);
		}
	}

	std::map<std::uint64_t, std::string> symbols;

	struct Frame {
		std::size_t node;
		std::string prefix;
		std::size_t depth;
	};

	for (std::size_t rootIndex = 0; rootIndex < nodes.size(); ++rootIndex) {
		if (childOffsets.count(nodes[rootIndex].offset) != 0) {
			continue;
		}
		std::vector<Frame> stack;
		stack.push_back(Frame{rootIndex, std::string(), 0});
		while (!stack.empty()) {
			Frame frame = std::move(stack.back());
			stack.pop_back();
			const Node &node = nodes[frame.node];

			if (node.hasAddress && !frame.prefix.empty()) {
				if (node.address == 0) continue;
				symbols[node.address] = frame.prefix;
			}

			for (std::size_t k = node.children.size(); k-- > 0;) {
				const Child &child = node.children[k];
				const auto found = nodeOffsetToNode.find(child.offset);
				if (found == nodeOffsetToNode.end()) {
					continue;
				}
				if (frame.depth + 1 >= nodes.size()) {
					throw std::runtime_error("Export trie contains a cycle");
				}
				stack.push_back(Frame{found->second, frame.prefix + child.suffix, frame.depth + 1});
			}
		}
	}

	std::string output;
	for (const auto &entry : symbols) {
		output += "0x";
		output += toHex(entry.first);
		output += ' ';
		output += entry.second;
		output += '\n';
	}
	writeWholeFile(fileName + PathString(kOutputSuffix), output);

	return symbols.size();
}

std::string baseName(const std::string &path) {
	const std::size_t separator = path.find_last_of("/\\");
	return separator == std::string::npos ? path : path.substr(separator + 1);
}

}

int main(int argc, char **argv) {
	const std::string programName = baseName((argc > 0 && argv != nullptr && argv[0] != nullptr) ? argv[0] : "SCSymbolizer");

	PathString fileName;
	ActionString action = kExportAction;
	PathString symbolsFileName;
	bool validArguments = false;

#ifdef _WIN32
	int wideArgc = 0;
	LPWSTR *wideArgv = CommandLineToArgvW(GetCommandLineW(), &wideArgc);
	if (wideArgv != nullptr) {
		if (wideArgc >= 3) {
			action = wideArgv[1];
			fileName = wideArgv[2];
			if (action == kImportAction && wideArgc >= 4) {
				symbolsFileName = wideArgv[3];
			}
			validArguments = true;
		}
		LocalFree(wideArgv);
	}
#else
	if (argc >= 3) {
		action = argv[1];
		fileName = argv[2];
		if (action == kImportAction && argc >= 4) {
			symbolsFileName = argv[3];  
		}
		validArguments = true;
	}
#endif

	if (!validArguments) {
		std::cout << "Usage: " << programName << " <action [export|import]> <file> [symbols file]" << std::endl;
		return 1;
	}
	if (action == kExportAction) {
		try {
			const std::size_t count = extractSymbols(fileName);
			std::cout << "Exported " << count << " symbols to " << displayPath(fileName) << displayPath(kOutputSuffix) << std::endl;
		} catch (const std::exception &error) {
			std::cerr << "Error: " << error.what() << std::endl;
			return 1;
		}
	} else if (action == kImportAction) {
		MachO::process(displayPath(fileName), displayPath(symbolsFileName), displayPath(fileName) + ".symbolized");
		return 1;
	} else {
		std::cerr << "Unknown action: " << std::string(action.begin(), action.end()) << std::endl;
		return 1;
	}
	return 0;
}
