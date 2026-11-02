#pragma once

#include <string>

namespace MachO {
    void process(
        const std::string& inputPath,
        const std::string& symbolPath,
        const std::string& outputPath
    );
}
