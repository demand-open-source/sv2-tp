# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_executable(fuzz)

# Minimal SV2-only fuzz target. Do not link the generic fuzz library or bitcoin_node.
target_sources(fuzz
  PRIVATE
    fuzz.cpp
    sv2_noise.cpp
    check_globals.cpp
    ../sv2_test_setup.cpp
)

target_link_libraries(fuzz
  core_interface
  fuzzer_interface
  bitcoin_common
  bitcoin_util
  bitcoin_sv2
  secp256k1
  Boost::headers
  test_util
)

if(NOT FUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION)
  target_compile_definitions(fuzz PRIVATE PROVIDE_FUZZ_MAIN_FUNCTION)
endif()
