// SPDX-License-Identifier: MIT
// Original OGVul teaching code; not a paper benchmark excerpt.
#include <cstddef>
#include <cstring>

struct TelemetryFrame {
    char payload[32];
};

bool receive_telemetry(TelemetryFrame* frame, const char* input,
                       std::size_t length) {
    if (frame == nullptr || input == nullptr) {
        return false;
    }
    std::memcpy(frame->payload, input, length);
    return true;
}
