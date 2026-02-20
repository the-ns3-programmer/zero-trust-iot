
#include "ns3/zt-encryption-utils.h"
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

namespace ns3 {

using namespace CryptoPP;

/**
 * \brief Encrypts a plaintext string using AES-CBC mode with a randomly generated IV.
 *
 * \param data The plaintext data to encrypt.
 * \param key The AES key used for encryption.
 * \param ivOut Reference to store the generated IV.
 * \return The resulting ciphertext with the IV prepended.
 */
std::string EncryptPayload(const std::string& data, const byte* key, std::string& ivOut) {
  AutoSeededRandomPool prng;
  byte iv[AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));
  ivOut.assign((char*)iv, AES::BLOCKSIZE);

  std::string cipher;
  CBC_Mode<AES>::Encryption enc;
  enc.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

  StringSource(data, true,
    new StreamTransformationFilter(enc,
      new StringSink(cipher)
    )
  );

  return ivOut + cipher;  // prepend IV to ciphertext
}

/**
 * \brief Decrypts a ciphertext string encrypted with EncryptPayload.
 *
 * \param cipher The ciphertext with the IV prepended.
 * \param key The AES key used for decryption.
 * \return The decrypted plaintext string.
 */
std::string DecryptPayload(const std::string& cipher, const byte* key) {
  std::string iv = cipher.substr(0, AES::BLOCKSIZE);
  std::string actualCipher = cipher.substr(AES::BLOCKSIZE);

  std::string recovered;
  CBC_Mode<AES>::Decryption dec;
  dec.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, (const byte*)iv.data());

  StringSource(actualCipher, true,
    new StreamTransformationFilter(dec,
      new StringSink(recovered)
    )
  );

  return recovered;
}

/**
 * \brief Decodes a hex-encoded AES key string into a raw key byte block.
 *
 * \param hex Hexadecimal string representing the AES key.
 * \return A Crypto++ SecByteBlock containing the decoded key.
 */
SecByteBlock HexDecodeKey(const std::string& hex) {
  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  StringSource(hex, true,
    new HexDecoder(new ArraySink(key, key.size())));
  return key;
}

/**
 * \brief Converts a hexadecimal string into a byte vector.
 *
 * \param hex The hexadecimal string to convert.
 * \return A vector of bytes corresponding to the decoded hex string.
 */
std::vector<CryptoPP::byte> HexToBytes(const std::string& hex) {
  std::string decoded;
  CryptoPP::StringSource(hex, true,
    new CryptoPP::HexDecoder(
      new CryptoPP::StringSink(decoded)
    )
  );

  return std::vector<CryptoPP::byte>(decoded.begin(), decoded.end());
}

} // namespace ns3

