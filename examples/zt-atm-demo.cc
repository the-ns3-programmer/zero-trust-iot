#include "ns3/core-module.h"
#include "ns3/network-module.h"

#include "ns3/zt-policy-engine.h"
#include "ns3/zt-identity-registry.h"

using namespace ns3;

int main(int argc, char *argv[])
{
  CommandLine cmd;
  cmd.Parse(argc, argv);

  /* =========================
     Create 3 Nodes
  ========================== */

  NodeContainer nodes;
  nodes.Create(3);

  Ptr<Node> atm      = nodes.Get(0);
  Ptr<Node> coreBank = nodes.Get(1);
  Ptr<Node> attacker = nodes.Get(2);

  std::cout << "Total Nodes: "
            << NodeList::GetNNodes()
            << "\n\n";

  /* =========================
     Register Identities
  ========================== */

  IdentityRegistry& registry =
      IdentityRegistry::GetInstance();

  registry.RegisterNode(atm, "ATM");
  registry.RegisterNode(coreBank, "CoreBank");
  registry.RegisterNode(attacker, "Attacker");

  std::cout << "ATM Hash: "
            << registry.GetIdentityHash(atm) << "\n";
  std::cout << "CoreBank Hash: "
            << registry.GetIdentityHash(coreBank) << "\n";
  std::cout << "Attacker Hash: "
            << registry.GetIdentityHash(attacker) << "\n\n";

  /* =========================
     Create Policy Engine
  ========================== */

  Ptr<ZtPolicyEngine> engine =
      CreateObject<ZtPolicyEngine>();

  /* =========================
     POLICY RULE 1 — ATM Withdraw ALLOW
  ========================== */

  ZtPolicyEngine::RolePolicyRule rule1;
  rule1.srcRole       = "ATM";
  rule1.dstRole       = "CoreBank";
  rule1.action        = "WITHDRAW";
  rule1.startHour     = 0;
  rule1.endHour       = 24;
  rule1.windowSeconds = 60;
  rule1.maxTransfers  = 5;
  rule1.effect        = ZtPolicyEngine::ALLOW;

  engine->AddRolePolicyRule(rule1);

  /* =========================
     POLICY RULE 2 — Attacker DENY
  ========================== */

  ZtPolicyEngine::RolePolicyRule rule2;
  rule2.srcRole       = "Attacker";
  rule2.dstRole       = "CoreBank";
  rule2.action        = "*";
  rule2.startHour     = 0;
  rule2.endHour       = 24;
  rule2.windowSeconds = 60;
  rule2.maxTransfers  = 0;
  rule2.effect        = ZtPolicyEngine::DENY;

  engine->AddRolePolicyRule(rule2);

  /* =========================
     Print Policy Metadata
  ========================== */

  std::cout << "Policy Version: "
            << engine->GetPolicyVersion()
            << "\n";

  std::cout << "Policy Integrity Hash (Φ): "
            << engine->GetPolicyIntegrityHash()
            << "\n\n";

  /* =========================
     TEST CASES
  ========================== */

  std::cout << "--- ATM Transaction Tests ---\n";

  bool decision1 =
      engine->EvaluateMicroSegmentation(
          atm, coreBank, "WITHDRAW");

  std::cout << "ATM Withdraw → "
            << (decision1 ? "ALLOW" : "DENY")
            << "\n";

  bool decision2 =
      engine->EvaluateMicroSegmentation(
          atm, coreBank, "TRANSFER");

  std::cout << "ATM Transfer → "
            << (decision2 ? "ALLOW" : "DENY")
            << "\n";

  bool decision3 =
      engine->EvaluateMicroSegmentation(
          attacker, coreBank, "WITHDRAW");

  std::cout << "Attacker Withdraw → "
            << (decision3 ? "ALLOW" : "DENY")
            << "\n";

  std::cout << "\nZero Trust Principle: Default = DENY\n";

  Simulator::Destroy();
  return 0;
}

