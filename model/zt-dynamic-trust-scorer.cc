#include "zt-dynamic-trust-scorer.h"
#include <sstream>
#include <cmath>
#include "ns3/simulator.h"

namespace ns3 {

/* ============================================================
 * Static Storage
 * ============================================================ */

std::map<uint64_t, ZtDynamicTrustScorer::TrustState>
    ZtDynamicTrustScorer::m_trustTable;

std::map<uint64_t, uint32_t>
    ZtDynamicTrustScorer::m_packetCounters;

/* ============================================================
 * Utility
 * ============================================================ */

uint64_t
ZtDynamicTrustScorer::MakeSessionKey(uint32_t srcNode,
                                     uint32_t dstNode)
{
    return (static_cast<uint64_t>(srcNode) << 32) | dstNode;
}

/* ============================================================
 * Core DTS Logic
 * ============================================================ */

void
ZtDynamicTrustScorer::OnPacketReceived(uint32_t srcNode,
                                       uint32_t dstNode,
                                       uint16_t protocol,
                                       uint16_t dstPort)
{
    const double ALPHA = 5.0;
    const double BETA  = 2.0;
    const double THRESHOLD = 25.0;

    uint64_t key = MakeSessionKey(srcNode, dstNode);
    TrustState &state = m_trustTable[key];

    if (state.blocked)
    {
        ZtLogger::Log("DTS", "Packet rejected — session blocked");
        return;
    }

    UpdateWindow(state, protocol, dstPort);
    double deviation = ComputeDeviation(state);

    if (!state.baselineInitialized)
    {
        state.baselinePacketRate = deviation;
        state.baselineInitialized = true;
        ZtLogger::Log("DTS", "Packet accepted (baseline learning)");
        return;
    }

    bool violation = (deviation > state.baselinePacketRate * 1.5);

    if (violation)
    {
        state.consecutiveViolations++;

        double penalty =
            ALPHA * std::pow(2, state.consecutiveViolations - 1);

        state.trustScore -= penalty;

        ZtLogger::Log("DTS", "Trust violation detected");

        if (state.consecutiveViolations > 1)
            ZtLogger::Log("DTS", "Repeated trust violation detected");

        ZtLogger::Log("DTS", "Packet dropped due to violation");
    }
    else
    {
        state.consecutiveViolations = 0;
        state.trustScore += BETA;
        ZtLogger::Log("DTS", "Packet accepted (normal behaviour)");
    }

    /* Clamp */
    if (state.trustScore < 0.0)
        state.trustScore = 0.0;

    if (state.trustScore > 100.0)
        state.trustScore = 100.0;

    std::ostringstream status;
    status << "Trust Score ("
           << srcNode << "->" << dstNode
           << "): " << state.trustScore;

    ZtLogger::Log("DTS", status.str());

    if (state.trustScore < THRESHOLD)
    {
        ZtLogger::Log("DTS",
            "Trust below threshold — blocking session");
        state.blocked = true;
    }
}

/* ============================================================
 * Traffic Generator (Merged Secure App)
 * ============================================================ */

void
ZtDynamicTrustScorer::StartTraffic(uint32_t srcNode,
                                   uint32_t dstNode)
{
    Simulator::Schedule(Seconds(1.0),
        &ZtDynamicTrustScorer::SendTraffic,
        srcNode, dstNode);
}

void
ZtDynamicTrustScorer::SendTraffic(uint32_t srcNode,
                                  uint32_t dstNode)
{
    uint64_t key = MakeSessionKey(srcNode, dstNode);
    m_packetCounters[key]++;

    if (!IsSessionAllowed(srcNode, dstNode))
    {
        ZtLogger::Log("DTS", "Packet blocked due to low trust");
        return;
    }

    uint32_t count = m_packetCounters[key];

    if (count <= 2)
    {
        ZtLogger::Log("DTS", "Normal packet");
        OnPacketReceived(srcNode, dstNode, 6, 8080);
    }
    else if (count <= 4)
    {
        ZtLogger::Log("DTS", "Consecutive violation burst");

        for (int i = 0; i < 3; i++)
            OnPacketReceived(srcNode, dstNode, 6, 8080);
    }
    else if (count == 5)
    {
        ZtLogger::Log("DTS", "Normal recovery packet");
        OnPacketReceived(srcNode, dstNode, 6, 8080);
    }

    Simulator::Schedule(Seconds(1.0),
        &ZtDynamicTrustScorer::SendTraffic,
        srcNode, dstNode);
}

/* ============================================================
 * Window + Deviation
 * ============================================================ */

void
ZtDynamicTrustScorer::UpdateWindow(TrustState &state,
                                   uint16_t protocol,
                                   uint16_t dstPort)
{
    double now = Simulator::Now().GetSeconds();

    state.window.push_back({now, protocol, dstPort});

    while (!state.window.empty() &&
           (now - state.window.front().timestamp) > 3.0)
    {
        state.window.pop_front();
    }
}

double
ZtDynamicTrustScorer::ComputeDeviation(
    const TrustState &state)
{
    if (state.window.empty())
        return 0.0;

    double duration =
        state.window.back().timestamp -
        state.window.front().timestamp;

    if (duration <= 0)
        return 0.0;

    return state.window.size() / duration;
}

bool
ZtDynamicTrustScorer::IsSessionAllowed(uint32_t srcNode,
                                       uint32_t dstNode)
{
    uint64_t key = MakeSessionKey(srcNode, dstNode);

    auto it = m_trustTable.find(key);

    if (it == m_trustTable.end())
        return true;

    return !(it->second.blocked);
}

} // namespace ns3

