#ifndef ZT_POLICY_ENGINE_H
#define ZT_POLICY_ENGINE_H

#include "ns3/object.h"
#include "ns3/node.h"

#include <vector>
#include <map>
#include <string>

namespace ns3 {

class ZtPolicyEngine : public Object
{
public:
  static TypeId GetTypeId();

  ZtPolicyEngine();
  virtual ~ZtPolicyEngine();

  /* ================================
     Rule Effect
  ================================= */
  enum RuleEffect
  {
    ALLOW = 0,
    DENY  = 1
  };

  /* ================================
     Role-Based Policy Rule
  ================================= */
  struct RolePolicyRule
  {
    std::string srcRole;
    std::string dstRole;
    std::string action;

    uint32_t startHour;
    uint32_t endHour;

    uint32_t windowSeconds;
    uint32_t maxTransfers;

    RuleEffect effect;
  };

  void AddRolePolicyRule(const RolePolicyRule& rule);

  bool EvaluateMicroSegmentation(
      Ptr<Node> srcNode,
      Ptr<Node> dstNode,
      const std::string& action);

  uint32_t GetPolicyVersion() const;

  std::string GetPolicyIntegrityHash() const;

private:
  bool IsWithinTime(uint32_t startHour,
                    uint32_t endHour);

  uint32_t GetBehaviorState(uint32_t nodeId,
                            uint32_t windowSeconds);

private:
  std::vector<RolePolicyRule> m_rules;

  std::map<uint32_t, std::vector<uint64_t>> m_transferHistory;

  uint32_t m_policyVersion;
};

} // namespace ns3

#endif // ZT_POLICY_ENGINE_H

