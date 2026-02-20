
#ifndef ZT_ENCRYPTION_UTILS_H
#define ZT_ENCRYPTION_UTILS_H

#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/config.h> 

namespace ns3 {

/**
 * \brief Encrypts the given plaintext using AES-CBC with a randomly generated IV.
 * 
 * \param data The plaintext to encrypt.
 * \param key Pointer to the AES key used for encryption.
 * \param ivOut Reference to store the generated IV used during encryption.
 * \return The ciphertext with the IV prepended.
 */
std::string EncryptPayload(const std::string& data, const CryptoPP::byte* key, std::string& ivOut);

/**
 * \brief Decrypts the given ciphertext using AES-CBC.
 * 
 * \param cipher The ciphertext with the IV prepended.
 * \param key Pointer to the AES key used for decryption.
 * \return The recovered plaintext string.
 */
std::string DecryptPayload(const std::string& cipher, const CryptoPP::byte* key);

/**
 * \brief Converts a hexadecimal string into a raw AES key.
 * 
 * \param hex The hex-encoded AES key string.
 * \return A CryptoPP SecByteBlock representing the decoded key.
 */
CryptoPP::SecByteBlock HexDecodeKey(const std::string& hex);

/**
 * \brief Converts a hexadecimal string into a byte vector.
 * 
 * \param hex The hex string to convert.
 * \return A vector of bytes decoded from the hexadecimal input.
 */
std::vector<CryptoPP::byte> HexToBytes(const std::string& hex);

} // namespace ns3

#endif // ZT_ENCRYPTION_UTILS_H

