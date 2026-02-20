/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This module provides a utility function to compute the SHA-256
 hash of a given input string using the Crypto++ library.

 - ComputeSha256():
   Generates a SHA-256 digest of the input data and returns
   it as a hexadecimal-encoded string.

 This is typically used for data integrity verification,
 authentication, or secure identity validation.
*/
#include "zt-hash-utils.h"

#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

namespace ns3 {

std::string
ComputeSha256(const std::string& input)
{
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(
        input,
        true,
        new CryptoPP::HashFilter(
            hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest),
                false
            )
        )
    );

    return digest;
}

}
