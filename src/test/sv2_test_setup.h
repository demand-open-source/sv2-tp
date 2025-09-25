// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_SV2_TEST_SETUP_H
#define BITCOIN_TEST_SV2_TEST_SETUP_H

#include <test/util/random.h>
#include <util/fs.h>
#include <memory>

class ECC_Context;

// Minimal test fixture for SV2 tests that avoids node/chainstate dependencies.
struct Sv2BasicTestingSetup {
    FastRandomContext m_rng;
    std::unique_ptr<ECC_Context> m_ecc;

    Sv2BasicTestingSetup();
    ~Sv2BasicTestingSetup();

private:
    fs::path m_tmp_root;
};

#endif // BITCOIN_TEST_SV2_TEST_SETUP_H
