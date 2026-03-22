#ifndef ZT_POLICY_ENGINE_H
#define ZT_POLICY_ENGINE_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <map>

#include <ns3/object.h>
#include <ns3/node.h>

#include <cryptopp/rsa.h>

using namespace CryptoPP;

namespace ns3 {

/**
 * \ingroup zerotrust
 * \brief Zero Trust Policy Engine with:
 * - Identity-based authorization
 * - Certificate validation
 * - Revocation support
 * - Micro-segmentation (custom extension)
 */
class ZtPolicyEngine : public Object
{
public:
  static TypeId GetTypeId();

  ZtPolicyEngine();
  virtual ~ZtPolicyEngine();

  /* =====================================================
     EXISTING FUNCTIONALITY (DO NOT MODIFY)
  ===================================================== */

  void AddAuthorized(uint32_t nodeId, const std::string& role);

  bool Authorize(uint32_t nodeId, const std::string& role);

  void SetCaPublicKey(RSA::PublicKey pub);

  void Revoke(uint32_t nodeId);

  bool AuthorizeWithCert(uint32_t nodeId,
                         const std::string& role,
                         const std::string& certStr);

  /* =====================================================
     NEW: MICRO-SEGMENTATION EXTENSION
  ===================================================== */

  enum RuleEffect
  {
    ALLOW = 0,
    DENY  = 1
  };

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
  /* ================= EXISTING ================= */
  std::unordered_map<uint32_t, std::string> authTable;
  std::unordered_set<uint32_t> revoke;
  RSA::PublicKey caPublicKey;

  /* ================= NEW ================= */
  bool IsWithinTime(uint32_t startHour,
                    uint32_t endHour);

  uint32_t GetBehaviorState(uint32_t nodeId,
                           uint32_t windowSeconds);

private:
  /* ================= NEW STORAGE ================= */
  std::vector<RolePolicyRule> m_rules;

  std::map<uint32_t, std::vector<uint64_t>> m_transferHistory;

  uint32_t m_policyVersion;
};

} // namespace ns3

#endif // ZT_POLICY_ENGINE_H
