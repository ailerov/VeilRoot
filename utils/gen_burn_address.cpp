#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "common/base58.h"
#include "crypto/hash.h"
#include <iostream>

int main() {
    // The H point (provably unspendable public key)
    const char H_hex[] = "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94";
    crypto::public_key H_key;
    epee::string_tools::hex_to_pod(H_hex, H_key);

    cryptonote::account_public_address burn_addr;
    burn_addr.m_spend_public_key = H_key;
    burn_addr.m_view_public_key = H_key;   // Use same H for view key

    std::string addr = cryptonote::get_account_address_as_str(cryptonote::MAINNET, false, burn_addr);
    std::cout << "Burn address: " << addr << std::endl;
    return 0;
}