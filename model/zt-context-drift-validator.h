// zt-context-drift-validator.h

/*
Authors: Rahul R, Dr. Subbulakshmi T, Arun Santhosh R A
Github id: Rahul2671
VIT Chennai, India
*/


/* 
The below code does the following:
Even after a node is authenticated and authorized successfully,
its access should NOT remain permanent. The node's operational
context is continuously monitored. If the context drifts too much
from the baseline captured during handshake, trust is gradually
reduced and access is revoked.
*/


#ifndef ZT_CONTEXT_DRIFT_VALIDATOR_H
#define ZT_CONTEXT_DRIFT_VALIDATOR_H

#include <map>
#include <set>
#include <cstdint>

#include "zt-policy-engine.h"   // MUST be here, before namespace

namespace ns3 {

/**
 * ============================================================
 * // Zero Trust Context Drift Validator
 * ============================================================
 */

/**
 * ============================================================
 * CLASS: ContextAttributeStore
 * ============================================================
 */
 
 // Stores baseline and runtime context of nodes

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
                      double wp) const;

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
 
 // Periodically evaluates node trust and revokes low-trust compromised nodes

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
  // Non-owning pointers (lifetime managed externally)

  std::set<uint32_t> activeNodes;

  double WT = 0.0;
  double WC = 0.0;
  double WP = 0.0;
  double LAMBDA = 0.0;
  double TRUST_THRESHOLD = 0.0;
};

} // namespace ns3

#endif // ZT_CONTEXT_DRIFT_VALIDATOR_H

