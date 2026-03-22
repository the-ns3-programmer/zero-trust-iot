
#include "ns3/core-module.h"
#include "ns3/network-module.h"

#include "ns3/zt-policy-engine.h"
#include "ns3/zt-identity-registry.h"

using namespace ns3;

int main(int argc, char *argv[])
{
  NodeContainer nodes;
  nodes.Create(3);

  Ptr<Node> camera = nodes.Get(0);
  Ptr<Node> analytics = nodes.Get(1);
  Ptr<Node> maintenance = nodes.Get(2);

  IdentityRegistry& registry = IdentityRegistry::GetInstance();

  registry.RegisterNode(camera, "Camera");
  registry.RegisterNode(analytics, "AnalyticsServer");
  registry.RegisterNode(maintenance, "MaintenanceDevice");

  Ptr<ZtPolicyEngine> engine = CreateObject<ZtPolicyEngine>();

  // Camera streaming rule
  ZtPolicyEngine::RolePolicyRule streamRule;
  streamRule.srcRole = "Camera";
  streamRule.dstRole = "AnalyticsServer";
  streamRule.action = "STREAM";
  streamRule.startHour = 0;
  streamRule.endHour = 24;
  streamRule.windowSeconds = 30;
  streamRule.maxTransfers = 5;
  streamRule.effect = ZtPolicyEngine::ALLOW;

  engine->AddRolePolicyRule(streamRule);

  // Maintenance update rule (restricted time window)
  ZtPolicyEngine::RolePolicyRule updateRule;
  updateRule.srcRole = "MaintenanceDevice";
  updateRule.dstRole = "AnalyticsServer";
  updateRule.action = "UPDATE";
  updateRule.startHour = 2; // 2 AM
  updateRule.endHour = 4; // 4 AM
  updateRule.windowSeconds = 60;
  updateRule.maxTransfers = 2;
  updateRule.effect = ZtPolicyEngine::ALLOW;

  engine->AddRolePolicyRule(updateRule);

  std::cout << "\n--- Dynamic Trust Enforcement Demo ---\n";

  // Valid streaming
  bool d1 = engine->EvaluateMicroSegmentation(camera, analytics, "STREAM");
  std::cout << "Camera STREAM → " << (d1 ? "ALLOW" : "DENY") << "\n";

  // Exceed stream threshold
  for (int i = 0; i < 6; ++i)
      engine->EvaluateMicroSegmentation(camera, analytics, "STREAM");

  bool d2 = engine->EvaluateMicroSegmentation(camera, analytics, "STREAM");
  std::cout << "Camera Excess STREAM → " << (d2 ? "ALLOW" : "DENY") << "\n";

  // Maintenance attempt (likely denied unless current hour is 2–4)
  bool d3 = engine->EvaluateMicroSegmentation(maintenance, analytics, "UPDATE");
  std::cout << "Maintenance UPDATE → " << (d3 ? "ALLOW" : "DENY") << "\n";

  // Unknown action
  bool d4 = engine->EvaluateMicroSegmentation(camera, analytics, "REBOOT");
  std::cout << "Camera REBOOT → " << (d4 ? "ALLOW" : "DENY") << "\n";

  return 0;
}
