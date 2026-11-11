// SPDX-License-Identifier: MIT
// Original OGVul teaching code; not a paper benchmark excerpt.
#include <cstdlib>

struct ValveState {
    int pressure;
};

void reset_valve_cache(bool drop_cache) {
    auto* state = static_cast<ValveState*>(std::malloc(sizeof(ValveState)));
    if (state == nullptr) {
        return;
    }
    state->pressure = 42;
    if (drop_cache) {
        std::free(state);
    }
    std::free(state);
}
