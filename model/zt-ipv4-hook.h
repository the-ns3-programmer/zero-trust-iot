/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This header defines the ZtIpv4Hook class used for
 integrating Zero Trust policy enforcement into
 the IPv4 transmission layer.

 - Inherits from ns3::Object.
 - Attaches to a node’s IPv4 stack.
 - Intercepts outgoing (Tx) packets.
 - Delegates access control decisions to the
   ZtPolicyEngine before packet transmission.

 This enables real-time micro-segmentation
 enforcement at the network layer.
*/
#ifndef ZT_IPV4_HOOK_H
#define ZT_IPV4_HOOK_H

#include "ns3/object.h"
#include "ns3/node.h"
#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/address.h"

namespace ns3 {

class ZtPolicyEngine;

class ZtIpv4Hook : public Object
{
public:
  static TypeId GetTypeId();

  ZtIpv4Hook();
  virtual ~ZtIpv4Hook();

  void SetPolicyEngine(Ptr<ZtPolicyEngine> engine);
  void AttachToNode(Ptr<Node> node);

private:
  // Correct Ipv4 Tx trace signature
  void InterceptPacket(Ptr<const Packet> packet,
                       Ptr<Ipv4> ipv4,
                       uint32_t interface);

  Ptr<ZtPolicyEngine> m_engine;
  Ptr<Node> m_node;
};

} // namespace ns3

#endif

