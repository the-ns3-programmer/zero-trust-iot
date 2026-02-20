#ifndef ZT_CONTEXT_DRIFT_VALIDATOR_H
#define ZT_CONTEXT_DRIFT_VALIDATOR_H

#include <map>
#include <set>
#include <cstdint>

#include "zt-policy-engine.h"   // MUST be here, before namespace

namespace ns3 {

/**
 * ============================================================
 * // Healthcare IoT Zero Trust Context Drift Validator
 * ============================================================
 */

/**
 * ============================================================
 * CLASS: ContextAttributeStore
 * ============================================================
 */
 
 // Stores clinical baseline and runtime context of medical devices

class ContextAttributeStore
{
public:

  void StoreBaseline(uint32_t nodeId,
                     double timeOfDay,
                     double congestion,
                     uint32_t proximity);

  void UpdateCurrentContext(uint32_t nodeId,
                            double timeOfDay,
                            double congestion,
                            uint32_t proximity);

  double CalculateDrift(uint32_t nodeId,
                        double wt,
                        double wc,
                        double wp);

  void UpdateTrust(uint32_t nodeId,
                   double drift,
                   double lambda);

  double GetTrust(uint32_t nodeId) const;

private:

  std::map<uint32_t, double> baselineTime;
  std::map<uint32_t, double> baselineCongestion;
  std::map<uint32_t, uint32_t> baselineProximity;

  std::map<uint32_t, double> currentTime;
  std::map<uint32_t, double> currentCongestion;
  std::map<uint32_t, uint32_t> currentProximity;

  std::map<uint32_t, double> trustScore;
};


/**
 * ============================================================
 * CLASS: PeriodicRevalidator
 * ============================================================
 */
 
 // Periodically evaluates medical device trust and revokes compromised nodes

class PeriodicRevalidator
{
public:

  PeriodicRevalidator(ZtPolicyEngine* policy,
                      ContextAttributeStore* store);

  void SetParameters(double wt,
                     double wc,
                     double wp,
                     double lambda,
                     double threshold);

  void AddActiveNode(uint32_t nodeId);

  void Revalidate();

private:

  ZtPolicyEngine* m_policy;
  ContextAttributeStore* m_store;

  std::set<uint32_t> activeNodes;

  double WT;
  double WC;
  double WP;

  double LAMBDA;
  double TRUST_THRESHOLD;
};

} // namespace ns3

#endif // ZT_CONTEXT_DRIFT_VALIDATOR_H

