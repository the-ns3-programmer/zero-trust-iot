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

