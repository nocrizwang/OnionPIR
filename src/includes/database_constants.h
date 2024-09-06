#pragma once

namespace DatabaseConstants {
constexpr int PolyDegree = 4096;
constexpr unsigned long long PlaintextMod = 16777259; // Use for 4096 (25 bits)
constexpr unsigned long long LargePlaintextMod = 442089503749; // Use for 8192 (39 bits)
} // namespace DatabaseConstants