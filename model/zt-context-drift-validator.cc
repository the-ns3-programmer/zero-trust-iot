// zt-context-drift-validator.cc
//
// This module implements Context-Drift–Based Continuous Authorization
// for a Zero Trust IoT Network (ZTN).
//
// Key idea:
// ---------
// Even after a node is authenticated and authorized successfully,
// its access should NOT remain permanent. The node's operational
// context is continuously monitored. If the context drifts too much
// from the baseline captured during handshake, trust is gradually
// reduced and access is revoked.
//
// This file is intentionally verbose and heavily commented
// to make the design and logic self-explanatory for reviewers,
// seniors, and future contributors.

//
// Healthcare IoT Context Drift Validator
//
// This module implements Continuous Zero-Trust Authorization
// for medical devices such as X-ray scanners, CT machines,
// and bedside patient monitoring systems.
//
// PROBLEM:
// --------
// Existing hospital IoT systems perform only one-time authentication.
// Once authenticated, devices can transmit sensitive medical data
// indefinitely even if their operational context changes.
//
// SOLUTION:
// ---------
// This system continuously evaluates device context using:
//
// 1. Time deviation (unauthorized operating hours)
// 2. Network congestion (possible attack or overload)
// 3. Physical proximity (device relocation)
//
// Mathematical Model:
//
// Drift D = wt*|Tcur − Tbase| + wc*|Ccur − Cbase| + wp*|Pcur − Pbase|
//
// Trust = Trust × exp(−λD)
//
// If Trust < Threshold → Device access revoked.
//
// This enables real-time revocation of compromised medical devices.
//


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
 
 // Baseline clinical operating context captured during device onboarding

void
ContextAttributeStore::StoreBaseline(uint32_t nodeId,
                                     double timeOfDay,
                                     double congestion,
                                     uint32_t proximity)
// Baseline captured when medical device is first authorized

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
  // Computes clinical context drift of medical IoT device

{
  // Time deviation: unauthorized usage window
  double dt = std::abs(currentTime[nodeId] - baselineTime[nodeId]);
  // Network deviation: congestion anomaly
  double dc = std::abs(currentCongestion[nodeId] - baselineCongestion[nodeId]);
  // Physical deviation: device movement
  double dp = std::abs((double)currentProximity[nodeId] -
                        (double)baselineProximity[nodeId]);

  return wt * dt + wc * dc + wp * dp;
}

void
ContextAttributeStore::UpdateTrust(uint32_t nodeId,
                                   double drift,
                                   double lambda)
    // Exponential decay of medical device trust score

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

    std::cout << "[Healthcare-ZT] MedicalDevice "
 << nodeId
              << " Drift=" << drift
              << " Trust=" << trust << std::endl;

    if (trust < TRUST_THRESHOLD)
    {
      m_policy->Revoke(nodeId);

      std::cout << "[Healthcare-ZT] MedicalDevice "
 << nodeId
                << " revoked due to low trust" << std::endl;
    }
  }
}

} 

