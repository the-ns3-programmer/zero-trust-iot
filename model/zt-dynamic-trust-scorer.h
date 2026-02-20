//zt-dynamic-trust-scorer.h

/*
Authors:Muthu Venkatesh M,Dr Subbulakshmi T,Arun Santhosh R A
Github id:muthuvenkatesh-24
VIT-Chennai
*/


/*
The function does the following:
• Maintains a trust score (0–100) per session (src → dst)
• Learns a baseline packet rate using a sliding time window
• Detects trust violations when deviation exceeds 1.5× baseline
• Applies exponential penalty for consecutive violations
• Rewards normal behaviour with gradual recovery
*/


#ifndef ZT_DYNAMIC_TRUST_SCORER_H
#define ZT_DYNAMIC_TRUST_SCORER_H

#include <map>
#include <deque>
#include <cstdint>

#include "zt-policy-engine.h"
#include "zt-logger.h"

namespace ns3 {

class ZtDynamicTrustScorer
{
public:

    /* ======== Core DTS ======== */

    static void OnPacketReceived(uint32_t srcNode,
                                 uint32_t dstNode,
                                 uint16_t protocol,
                                 uint16_t dstPort);

    static bool IsSessionAllowed(uint32_t srcNode,
                                 uint32_t dstNode);

    /* ======== Traffic Generator (Merged Secure App) ======== */

    static void StartTraffic(uint32_t srcNode,
                             uint32_t dstNode);

private:

    static void SendTraffic(uint32_t srcNode,
                            uint32_t dstNode);

    struct PacketObservation
    {
        double timestamp;
        uint16_t protocol;
        uint16_t dstPort;
    };

    struct TrustState
    {
        double trustScore;
        std::deque<PacketObservation> window;
        bool baselineInitialized;
        double baselinePacketRate;
        bool blocked;
        int consecutiveViolations;

        TrustState()
            : trustScore(100.0),
              baselineInitialized(false),
              baselinePacketRate(0.0),
              blocked(false),
              consecutiveViolations(0)
        {
        }
    };

    static std::map<uint64_t, TrustState> m_trustTable;
    static std::map<uint64_t, uint32_t>   m_packetCounters;

    static uint64_t MakeSessionKey(uint32_t srcNode, uint32_t dstNode);
    static void UpdateWindow(TrustState &state,
                             uint16_t protocol,
                             uint16_t dstPort);
    static double ComputeDeviation(const TrustState &state);
};

} // namespace ns3

#endif

