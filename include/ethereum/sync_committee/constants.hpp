#include <cstdlib>
#include <array>

constexpr static const std::size_t getNumBitsPerRegister = 55;
constexpr static const std::size_t getNumRegisters = 7;
constexpr static const std::size_t getSyncCommitteeSize = 512;
constexpr static const std::size_t getLog2SyncCommitteeSize = 9;
constexpr static const std::size_t getFinalizedHeaderDepth = 6;
constexpr static const std::size_t getFinalizedHeaderIndex = 105;
constexpr static const std::size_t getExecutionStateRootDepth = 8;
constexpr static const std::size_t getExecutionStateRootIndex = 402;
constexpr static const std::size_t getSyncCommitteeDepth = 5;
constexpr static const std::size_t getSyncCommitteeIndex = 55;
constexpr static const std::size_t getTruncatedSha256Size = 253;
constexpr static const std::size_t getG1PointSize = 48;
constexpr static const std::size_t getCurveA1 = 0;
constexpr static const std::size_t getCurveB1 = 4;

constexpr static const std::array<std::size_t, 43> getDomainSeperatorTag = {
    66, 76, 83, 95, 83, 73, 71, 95, 66, 76, 83, 49, 50, 51, 56, 49, 71, 50, 95, 88, 77, 68,
    58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85, 95, 82, 79, 95, 80, 79, 80, 95};

constexpr static const std::array<std::size_t, 7> getBLS128381Prime = {
    35747322042231467, 36025922209447795, 1084959616957103, 7925923977987733,
    16551456537884751, 23443114579904617, 1829881462546425};