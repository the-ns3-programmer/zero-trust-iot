#ifndef IDENTITY_REGISTRY_H
#define IDENTITY_REGISTRY_H

#include <map>
#include <string>
#include "ns3/node.h"

namespace ns3 {

class IdentityRegistry
{
public:
  static IdentityRegistry& GetInstance();

  void RegisterNode(Ptr<Node> node, const std::string& role);

  std::string GetIdentityHash(Ptr<Node> node) const;
  std::string GetRole(Ptr<Node> node) const;

private:
  IdentityRegistry() {}

  // nodeId -> (role, identityHash)
  std::map<uint32_t, std::pair<std::string, std::string>> m_identityMap;
};

}

#endif

