#include <cstdint>
#include "ns3/core-module.h"
#include "ns3/zt-context-drift-validator.h"
#include "ns3/zt-policy-engine.h"
#include "ns3/zt-logger.h"

#include <vector>

using namespace ns3;

ContextAttributeStore *g_store;
PeriodicRevalidator *g_validator;

std::vector<uint32_t> nodes = {1,2,3,4};

bool rareAttack = false;

/* --------------------------------
 * Deterministic Context Generator
 * -------------------------------- */
void UpdateContext ()
{
  for (auto nodeId : nodes)
  {
    double timeCtx;
    double congestion;
    uint32_t proximity;

    // ==========================
    // Node 4 → Rare extreme case
    // ==========================
    if (rareAttack && nodeId == 4)
    {
      timeCtx = 23;
      congestion = 0.99;
      proximity = 15;

      ZtLogger::Log("NORMAL-TEST", "Extreme drift (Node 4)");
    }

    // ==========================
    // Node 3 → Severe drift
    // ==========================
    else if (nodeId == 3)
    {
      timeCtx = 18;
      congestion = 0.75;
      proximity = 8;

      ZtLogger::Log("NORMAL-TEST", "Severe drift (Node 3)");
    }

    // ==========================
    // Node 2 → Mild drift
    // ==========================
    else if (nodeId == 2)
    {
      timeCtx = 12;
      congestion = 0.30;
      proximity = 3;

      ZtLogger::Log("NORMAL-TEST", "Mild drift (Node 2)");
    }

    // ==========================
    // Node 1 → Perfectly normal
    // ==========================
    else
    {
      timeCtx = 10;
      congestion = 0.10;
      proximity = 2;

      ZtLogger::Log("NORMAL-TEST", "Normal behavior (Node 1)");
    }

    g_store->UpdateCurrentContext(nodeId, timeCtx, congestion, proximity);
  }

  Simulator::Schedule(Seconds(1.0), &UpdateContext);
}

/* -------------------------------- */
void ValidateLoop ()
{
  g_validator->Revalidate();
  Simulator::Schedule(Seconds(1.0), &ValidateLoop);
}

/* -------------------------------- */
void TriggerRareAttack ()
{
  rareAttack = true;
  ZtLogger::Log("NORMAL-TEST", ">>> RARE ATTACK ACTIVATED <<<");
}

/* -------------------------------- */
int main(int argc, char *argv[])
{
  Time::SetResolution(Time::NS);

  ZtPolicyEngine policy;
  ContextAttributeStore store;

  for (auto n : nodes)
  {
    policy.AddAuthorized(n, "generic-device");
    policy.Authorize(n, "generic-device");

    store.StoreBaseline(n, 10, 0.10, 2);
  }

  PeriodicRevalidator validator(&policy, &store);

  validator.SetParameters(
      0.35, // time weight
      0.35, // congestion weight
      0.30, // proximity weight
      0.05, // lambda (UPDATED from 0.50 → 0.05)
      0.40 // trust threshold
  );

  for (auto n : nodes)
    validator.AddActiveNode(n);

  g_store = &store;
  g_validator = &validator;

  Simulator::Schedule(Seconds(1.0), &UpdateContext);
  Simulator::Schedule(Seconds(2.0), &ValidateLoop);

  Simulator::Schedule(Seconds(8.0), &TriggerRareAttack);

  Simulator::Stop(Seconds(18.0));
  Simulator::Run();
  Simulator::Destroy();

  return 0;
}
