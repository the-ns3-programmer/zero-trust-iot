#include "zt-policy-engine.h"
#include "zt-identity-registry.h"
#include "zt-hash-utils.h"

#include <ctime>
#include <algorithm>
#include <sstream>
#include <iostream>

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(ZtPolicyEngine);

TypeId
ZtPolicyEngine::GetTypeId()
{
  static TypeId tid =
      TypeId("ns3::ZtPolicyEngine")
          .SetParent<Object>()
          .AddConstructor<ZtPolicyEngine>();
  return tid;
}

ZtPolicyEngine::ZtPolicyEngine()
  : m_policyVersion(0)
{
}

ZtPolicyEngine::~ZtPolicyEngine()
{
}

void
ZtPolicyEngine::AddRolePolicyRule(const RolePolicyRule& rule)
{
  m_rules.push_back(rule);
  m_policyVersion++;

  std::cout << "[POLICY] Rule Added. Version: "
            << m_policyVersion << "\n";
}

bool
ZtPolicyEngine::IsWithinTime(uint32_t startHour,
                             uint32_t endHour)
{
  std::time_t now = std::time(nullptr);
  std::tm* local = std::localtime(&now);
  uint32_t hour = local->tm_hour;

  return (hour >= startHour && hour < endHour);
}

uint32_t
ZtPolicyEngine::GetBehaviorState(uint32_t nodeId,
                                 uint32_t windowSeconds)
{
  uint64_t now = std::time(nullptr);
  auto& history = m_transferHistory[nodeId];

  history.erase(
      std::remove_if(history.begin(),
                     history.end(),
                     [&](uint64_t t)
                     { return now - t > windowSeconds; }),
      history.end());

  return history.size();
}

bool
ZtPolicyEngine::EvaluateMicroSegmentation(
    Ptr<Node> srcNode,
    Ptr<Node> dstNode,
    const std::string& action)
{
  if (!srcNode || !dstNode)
  {
    std::cout << "[MICRO-SEG] Invalid Node Pointer\n";
    return false;
  }

  IdentityRegistry& registry =
      IdentityRegistry::GetInstance();

  std::string Hs = registry.GetIdentityHash(srcNode);
  std::string Hd = registry.GetIdentityHash(dstNode);

  std::string srcRole = registry.GetRole(srcNode);
  std::string dstRole = registry.GetRole(dstNode);

  uint32_t nodeId = srcNode->GetId();

  std::time_t now = std::time(nullptr);
  std::tm* local = std::localtime(&now);
  uint32_t currentHour = local->tm_hour;

  for (const auto& rule : m_rules)
  {
    if (rule.srcRole == srcRole &&
        rule.dstRole == dstRole &&
        (rule.action == action || rule.action == "*"))
    {
      if (!IsWithinTime(rule.startHour, rule.endHour))
        continue;

      uint32_t transferCount =
          GetBehaviorState(nodeId, rule.windowSeconds);

      uint32_t behaviorState =
          (transferCount <= rule.maxTransfers) ? 0 : 1;

      std::string S =
          Hs + Hd +
          action +
          std::to_string(currentHour) +
          rule.srcRole +
          rule.dstRole +
          std::to_string(behaviorState);

      std::string Psi =
          ns3::ComputeSha256(S);

      std::cout << "[MICRO-SEG] Ψ: "
                << Psi << "\n";

      if (behaviorState == 0 &&
          rule.effect == ALLOW)
      {
        if (action == "TRANSFER" ||
            action == "WITHDRAW")
        {
          m_transferHistory[nodeId].push_back(now);
        }

        return true;
      }

      if (rule.effect == DENY)
      {
        return false;
      }
    }
  }

  std::cout << "[MICRO-SEG] Default DENY (Least Privilege)\n";
  return false;
}

uint32_t
ZtPolicyEngine::GetPolicyVersion() const
{
  return m_policyVersion;
}

std::string
ZtPolicyEngine::GetPolicyIntegrityHash() const
{
  std::stringstream ss;

  ss << m_policyVersion;

  for (const auto& rule : m_rules)
  {
    ss << rule.srcRole
       << rule.dstRole
       << rule.action
       << rule.startHour
       << rule.endHour
       << rule.windowSeconds
       << rule.maxTransfers
       << rule.effect;
  }

  return ns3::ComputeSha256(ss.str());
}

} // namespace ns3

