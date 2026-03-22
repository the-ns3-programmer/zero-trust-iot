/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This header defines the IdentityRegistry class used for
 managing node identities in a Zero Trust network.

 - Implements a singleton pattern to ensure a single
   centralized identity registry.

 - Stores mapping of node ID to:
     (assigned role, SHA-256 identity hash).

 - Provides functions to register nodes and retrieve
   their role or identity hash.

 This supports secure identity verification and
 role-based access enforcement.
*/
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

