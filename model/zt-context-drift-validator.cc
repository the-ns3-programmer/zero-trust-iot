// zt-context-drift-validator.cc

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


#include "zt-context-drift-validator.h"
#include "zt-policy-engine.h"

#include <cmath>
#include <iostream>

namespace ns3 {

/**
 * ============================================================
 * ContextAttributeStore IMPLEMENTATION
 * ============================================================
 */
 
 // Baseline operating context captured during node onboarding

void
ContextAttributeStore::StoreBaseline(uint32_t nodeId,
                                     double timeOfDay,
                                     double congestion,
                                     uint32_t proximity)
// Baseline captured when node is first authorized

{
  baselineTime[nodeId] = timeOfDay;
  baselineCongestion[nodeId] = congestion;
  baselineProximity[nodeId] = proximity;

  currentTime[nodeId] = timeOfDay;
  currentCongestion[nodeId] = congestion;
  currentProximity[nodeId] = proximity;

  trustScore[nodeId] = 1.0;
}

void
ContextAttributeStore::UpdateCurrentContext(uint32_t nodeId,
                                            double timeOfDay,
                                            double congestion,
                                            uint32_t proximity)
{
  currentTime[nodeId] = timeOfDay;
  currentCongestion[nodeId] = congestion;
  currentProximity[nodeId] = proximity;
}

double
ContextAttributeStore::CalculateDrift(uint32_t nodeId,
                                      double wt,
                                      double wc,
                                      double wp)

{
  // Time deviation
  double dt = std::abs(currentTime[nodeId] - baselineTime[nodeId]);
  // Network deviation
  double dc = std::abs(currentCongestion[nodeId] - baselineCongestion[nodeId]);
  // Location deviation
  double dp = std::abs((double)currentProximity[nodeId] -
                        (double)baselineProximity[nodeId]);

  return wt * dt + wc * dc + wp * dp;
}

void
ContextAttributeStore::UpdateTrust(uint32_t nodeId,
                                   double drift,
                                   double lambda)
{
  trustScore[nodeId] *= std::exp(-lambda * drift);

  if (trustScore[nodeId] < 0.0)
    trustScore[nodeId] = 0.0;
}

double
ContextAttributeStore::GetTrust(uint32_t nodeId) const
{
  auto it = trustScore.find(nodeId);
  if (it != trustScore.end())
    return it->second;

  return 0.0;
}

/**
 * ============================================================
 * PeriodicRevalidator IMPLEMENTATION
 * ============================================================
 */ 

PeriodicRevalidator::PeriodicRevalidator(ZtPolicyEngine* policy,
                                         ContextAttributeStore* store)
{
  m_policy = policy;
  m_store = store;
}

void
PeriodicRevalidator::SetParameters(double wt,
                                   double wc,
                                   double wp,
                                   double lambda,
                                   double threshold)
{
  WT = wt;
  WC = wc;
  WP = wp;
  LAMBDA = lambda;
  TRUST_THRESHOLD = threshold;
}

void
PeriodicRevalidator::AddActiveNode(uint32_t nodeId)
{
  activeNodes.insert(nodeId);
}

void
PeriodicRevalidator::Revalidate()
{
  for (auto nodeId : activeNodes)
  {
    double drift = m_store->CalculateDrift(nodeId, WT, WC, WP);

    m_store->UpdateTrust(nodeId, drift, LAMBDA);

    double trust = m_store->GetTrust(nodeId);

    std::cout << "[ZeroTrust] Node"
 << nodeId
              << " Drift=" << drift
              << " Trust=" << trust << std::endl;

    if (trust < TRUST_THRESHOLD)

      m_policy->Revoke(nodeId);

      std::cout << "[ZeroTrust] Node "
 << nodeId
                << " revoked due to low trust" << std::endl;
    }
  }
}

} 

