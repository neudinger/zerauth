#pragma once

#ifndef CRYPTO_TOOL_HPP
#define CRYPTO_TOOL_HPP

#include <openssl/bn.h>       // for BN_new, BN_free
#include <openssl/crypto.h>   // for OPENSSL_secure_clea...
#include <openssl/ec.h>       // for EC_POINT_new, EC_PO...
#include <openssl/evp.h>      // for EVP_DigestUpdate
#include <openssl/obj_mac.h>  // for NID_undef
#include <openssl/objects.h>  // for OBJ_sn2nid, OBJ_nid2ln
#include <openssl/sha.h>      // for SHA256_DIGEST_LENGTH
#include <openssl/types.h>    // for BIGNUM, BN_CTX, EVP_MD

#include <cstdint>  // for uint8_t, uint64_t
#include <cstdlib>  // for EXIT_FAILURE, size_t
#include <cstring>  // for memcpy, strlen
#include <memory>   // for unique_ptr, operator==

namespace crypto {

using char_unique_ptr = typename std::unique_ptr<char, decltype(&::free)>;
using buf_unique_ptr = typename std::unique_ptr<uint8_t, decltype(&::free)>;
using EVP_PKEY_unique_ptr =
    typename std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVP_PKEY_CTX_unique_ptr =
    typename std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EVP_MD_CTX_unique_ptr =
    typename std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;
using EVP_MD_unique_ptr =
    typename std::unique_ptr<EVP_MD, decltype(&::EVP_MD_free)>;
using BN_CTX_unique_ptr =
    typename std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)>;
using BN_unique_ptr = typename std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using EC_GROUP_unique_ptr =
    typename std::unique_ptr<EC_GROUP, decltype(&::EC_GROUP_free)>;
using EC_POINT_unique_ptr =
    typename std::unique_ptr<EC_POINT, decltype(&::EC_POINT_free)>;
using OSSL_LIB_CTX_ptr =
    typename std::unique_ptr<OSSL_LIB_CTX, decltype(&::OSSL_LIB_CTX_free)>;
inline auto crypto_char_free(void *const ptr) -> void { OPENSSL_free(ptr); }
using CRYPTO_char_unique_ptr =
    typename std::unique_ptr<char, decltype(&crypto::crypto_char_free)>;

}  // namespace crypto

#endif /* CRYPTO_TOOL_HPP */