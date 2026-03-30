//zt-trust-test.cc

/*
Authors:Muthu Venkatesh M,Dr Subbulakshmi T,Arun Santhosh R A
Github id:muthuvenkatesh-24
VIT-Chennai
*/


/*

The test does the following:

• Checks whether the function maintains a trust score (0–100) per session (src → dst)
• Learns a baseline packet rate using a sliding time window
• Detects trust violations when deviation exceeds 1.5× baseline
• Checks with regard to different types of attacks(Normal Behaviour , Violation Burst)
• Applies exponential penalty for consecutive violations
• Rewards normal behaviour with gradual recovery
• Blocks the session and rejects the packets if trust score is below the threshold

*/


#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/zero-trust-iot-module.h"

using namespace ns3;

static void SendNormal(uint32_t src, uint32_t dst)
{
    std::cout << "Normal packet" << std::endl;
    ZtDynamicTrustScorer::OnPacketReceived(src, dst, 6, 8080);
}

static void SendBurst(uint32_t src, uint32_t dst)
{
    std::cout << "Violation burst" << std::endl;

    for (int i = 0; i < 5; ++i)
    {
        Simulator::Schedule(MilliSeconds(i * 50),
            &ZtDynamicTrustScorer::OnPacketReceived,
            src, dst, 6, 8080);
    }
}

int main()
{
    uint32_t src = 0;
    uint32_t dst = 1;

    Simulator::Schedule(Seconds(1.0), &SendNormal, src, dst);
    Simulator::Schedule(Seconds(2.0), &SendNormal, src, dst);
    Simulator::Schedule(Seconds(3.0), &SendBurst,  src, dst);
    Simulator::Schedule(Seconds(7.0), &SendNormal, src, dst);
    Simulator::Schedule(Seconds(8.0), &SendBurst,  src, dst);

    Simulator::Stop(Seconds(15.0));
    Simulator::Run();
    Simulator::Destroy();
}

