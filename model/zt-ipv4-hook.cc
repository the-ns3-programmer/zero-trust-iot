/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This module implements an IPv4 hook for enforcing
 Zero Trust micro-segmentation policies at the IP layer.

 - Attaches to a node’s IPv4 stack and intercepts
   outgoing (Tx) packets.

 - Uses the ZtPolicyEngine to evaluate communication
   between source and destination nodes.

 - Logs ALLOW or DENY decisions based on policy rules.

 This enables runtime policy enforcement directly
 at the network transmission layer.
*/
#include "zt-ipv4-hook.h"
#include "zt-policy-engine.h"
#include "zt-identity-registry.h"

#include "ns3/node-list.h"
#include "ns3/log.h"
#include "ns3/ipv4.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(ZtIpv4Hook);

TypeId
ZtIpv4Hook::GetTypeId()
{
  static TypeId tid =
      TypeId("ns3::ZtIpv4Hook")
          .SetParent<Object>()
          .AddConstructor<ZtIpv4Hook>();
  return tid;
}

ZtIpv4Hook::ZtIpv4Hook() {}
ZtIpv4Hook::~ZtIpv4Hook() {}

void
ZtIpv4Hook::SetPolicyEngine(Ptr<ZtPolicyEngine> engine)
{
  m_engine = engine;
}

void
ZtIpv4Hook::AttachToNode(Ptr<Node> node)
{
  m_node = node;

  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  if (ipv4 == nullptr)
  {
    std::cout << "[ZT-NETWORK] No IPv4 stack found\n";
    return;
  }

  ipv4->TraceConnectWithoutContext(
      "Tx",
      MakeCallback(&ZtIpv4Hook::InterceptPacket, this));
}

void
ZtIpv4Hook::InterceptPacket(
    Ptr<const Packet> packet,
    Ptr<Ipv4> ipv4,
    uint32_t interface)
{
  if (m_engine == nullptr || m_node == nullptr)
    return;

  // Demo: assume destination node 1
  if (NodeList::GetNNodes() < 2)
    return;

  Ptr<Node> srcNode = m_node;
  Ptr<Node> dstNode = NodeList::GetNode(1);

  bool decision =
      m_engine->EvaluateMicroSegmentation(
          srcNode,
          dstNode,
          "TRANSFER");

  if (!decision)
  {
    std::cout << "[ZT-NETWORK] Policy DENY at IP layer\n";
  }
  else
  {
    std::cout << "[ZT-NETWORK] Policy ALLOW at IP layer\n";
  }
}

} // namespace ns3

