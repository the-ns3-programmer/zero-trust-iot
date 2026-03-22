/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This module implements a singleton Identity Registry used
 to manage node identities in the Zero Trust architecture.

 - GetInstance():
   Provides a single global instance of the registry.

 - RegisterNode():
   Registers a node with its role and generates a SHA-256
   identity hash based on node ID and role.

 - GetIdentityHash():
   Retrieves the stored identity hash for a node.

 - GetRole():
   Retrieves the assigned role of a node.

 This enables secure identity tracking and role-based
 validation within the network.
*/
#include "zt-identity-registry.h"
#include "zt-hash-utils.h"

namespace ns3 {

IdentityRegistry&
IdentityRegistry::GetInstance()
{
  static IdentityRegistry instance;
  return instance;
}

void
IdentityRegistry::RegisterNode(Ptr<Node> node, const std::string& role)
{
  std::string input = std::to_string(node->GetId()) + role;
  std::string hash = ComputeSha256(input);

  m_identityMap[node->GetId()] = {role, hash};
}

std::string
IdentityRegistry::GetIdentityHash(Ptr<Node> node) const
{
  auto it = m_identityMap.find(node->GetId());
  if (it != m_identityMap.end())
    return it->second.second;

  return "";
}

std::string
IdentityRegistry::GetRole(Ptr<Node> node) const
{
  auto it = m_identityMap.find(node->GetId());
  if (it != m_identityMap.end())
    return it->second.first;

  return "";
}

} // namespace ns3

