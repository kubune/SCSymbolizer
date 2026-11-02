#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

class ByteStream {
public:
	enum class Endian { Little, Big };

	std::uint64_t offset = 0;
	Endian endian;

	explicit ByteStream(std::vector<std::uint8_t> buffer = {}, Endian endianness = Endian::Little)
		: endian(endianness), buffer_(std::move(buffer)) {}

	std::uint64_t size() const { return static_cast<std::uint64_t>(buffer_.size()); }

	bool isAtEnd() const { return offset >= size(); }

	const std::uint8_t *readBytes(std::uint64_t count) {
		const std::uint64_t total = size();
		if (offset > total || count > total - offset) {
			throw std::runtime_error("Not enough bytes to read");
		}
		const std::uint8_t *result = buffer_.data() + offset;
		offset += count;
		return result;
	}

	std::uint64_t readUInt(unsigned count) {
		if (count > 8) {
			throw std::invalid_argument("readUInt supports at most 8 bytes");
		}
		const std::uint8_t *bytes = readBytes(count);
		std::uint64_t result = 0;
		if (endian == Endian::Big) {
			for (unsigned i = 0; i < count; ++i) {
				result = (result << 8) | bytes[i];
			}
		} else {
			for (unsigned i = count; i-- > 0;) {
				result = (result << 8) | bytes[i];
			}
		}
		return result;
	}

	std::uint8_t readUInt8() { return static_cast<std::uint8_t>(readUInt(1)); }
	std::uint16_t readUInt16() { return static_cast<std::uint16_t>(readUInt(2)); }
	std::uint32_t readUInt32() { return static_cast<std::uint32_t>(readUInt(4)); }
	std::uint64_t readUInt64() { return readUInt(8); }

	std::string readCString() {
		const std::uint64_t total = size();
		const void *terminator = nullptr;
		if (offset < total) {
			terminator = std::memchr(buffer_.data() + offset, 0, static_cast<std::size_t>(total - offset));
		}
		if (terminator == nullptr) {
			throw std::runtime_error("End terminator not found");
		}
		const char *start = reinterpret_cast<const char *>(buffer_.data() + offset);
		const std::size_t length = static_cast<std::size_t>(static_cast<const std::uint8_t *>(terminator) - (buffer_.data() + offset));
		std::string result(start, length);
		offset += length + 1;
		return result;
	}

	std::uint64_t readULEB128() {
		std::uint64_t result = 0;
		unsigned shift = 0;
		while (true) {
			const std::uint64_t bits = readUInt8() & 0x7Fu;
			const bool more = (buffer_[static_cast<std::size_t>(offset - 1)] & 0x80u) != 0;
			if (shift < 64) {
				if (shift > 0 && ((bits << shift) >> shift) != bits) {
					throw std::runtime_error("ULEB128 value does not fit in 64 bits");
				}
				result |= bits << shift;
				shift += 7;
			} else if (bits != 0) {
				throw std::runtime_error("ULEB128 value does not fit in 64 bits");
			}
			if (!more) {
				break;
			}
		}
		return result;
	}

private:
	std::vector<std::uint8_t> buffer_;
};
