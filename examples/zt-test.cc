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

