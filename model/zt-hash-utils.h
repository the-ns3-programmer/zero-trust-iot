#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <string>

namespace ns3 {

std::string ComputeSha256(const std::string& input);

}

#endif
