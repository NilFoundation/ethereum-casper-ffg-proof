#include <cstdlib>
#include <array>

constexpr static const std::size_t NUM_BITS_PER_REGISTER = 55;
constexpr static const std::size_t NUM_REGISTERS = 7;
constexpr static const std::size_t SYNC_COMMITTEE_SIZE = 512;
constexpr static const std::size_t LOG2_SYNC_COMMITTEE_SIZE = 9;
constexpr static const std::size_t FINALIZED_HEADER_DEPTH = 6;
constexpr static const std::size_t FINALIZED_HEADER_INDEX = 105;
constexpr static const std::size_t EXECUTION_STATE_ROOT_DEPTH = 8;
constexpr static const std::size_t EXECUTION_STATE_ROOT_INDEX = 402;
constexpr static const std::size_t SYNC_COMMITTEE_DEPTH = 5;
constexpr static const std::size_t SYNC_COMMITTEE_INDEX = 55;
constexpr static const std::size_t TRUNCATED_SHA256_SIZE = 253;
constexpr static const std::size_t G1_POINT_SIZE = 48;
constexpr static const std::size_t CURVE_A1 = 0;
constexpr static const std::size_t CURVE_B1 = 4;

constexpr static const std::size_t DOMAIN_SEPERATOR_TAG_SIZE = 43;
constexpr static const std::array<std::size_t, DOMAIN_SEPERATOR_TAG_SIZE> DOMAIN_SEPERATOR_TAG = {
        66, 76, 83, 95, 83, 73, 71, 95, 66, 76, 83, 49, 50, 51, 56, 49, 71, 50, 95, 88, 77, 68,
        58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85, 95, 82, 79, 95, 80, 79, 80, 95};

constexpr static const std::array<std::size_t, 7> BLS128381_PRIME = {
        35747322042231467, 36025922209447795, 1084959616957103, 7925923977987733,
        16551456537884751, 23443114579904617, 1829881462546425};

constexpr static const std::size_t BLS12381_PARAMETER = 15132376222941642752;