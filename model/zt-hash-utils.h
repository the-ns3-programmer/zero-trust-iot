/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This header declares the SHA-256 hashing utility function
 used for data integrity and security verification.

 - ComputeSha256():
   Computes and returns the SHA-256 hash of an input string
   as a hexadecimal-encoded digest.

 This function supports secure identity validation and
 integrity checking in the system.
*/
#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <string>

namespace ns3 {

std::string ComputeSha256(const std::string& input);

}

#endif
