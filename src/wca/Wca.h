#ifndef __INET_WCA_H
#define __INET_WCA_H

#include "inet/common/INETDefs.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/ipv4/IIpv4RoutingTable.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/power/contract/IEpEnergyStorage.h"
#include <map>
#include <set>
#include "WcaPacket_m.h"

namespace hwca {

using namespace inet;

struct NeighborInfo {
    Ipv4Address address;
    double weight;
    int nodeDegree;
    double transmissionPower;
    double mobility;
    double batteryPower;
    simtime_t lastSeen;
    Coord position;
    Coord previousPosition;
};

class INET_API Wca : public cSimpleModule, public NetfilterBase::HookBase
{
  private:
    // Module references
    IInterfaceTable *interfaceTable = nullptr;
    IIpv4RoutingTable *routingTable = nullptr;
    IMobility *mobility = nullptr;
    power::IEpEnergyStorage *energyStorage = nullptr;

    // Network interface
    NetworkInterface *interface80211 = nullptr;

    // Parameters
    double helloInterval;
    double clusterTimeout;
    double maxTransmissionPower;
    double degreeWeight;
    double transmissionWeight;
    double mobilityWeight;
    double batteryWeight;
    double radioRange;

    // State variables
    bool isClusterHead;
    Ipv4Address myClusterHead;
    Ipv4Address myAddress;
    std::map<Ipv4Address, NeighborInfo> neighbors;
    std::set<Ipv4Address> clusterMembers;
    double myWeight;
    Coord previousPosition;
    simtime_t lastMobilityUpdate;

    // Timers
    cMessage *helloTimer = nullptr;
    cMessage *clusterTimer = nullptr;

    // Statistics
    simsignal_t clusterHeadChangedSignal;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Packet processing
    virtual void processHelloPacket(Packet *packet);
    virtual void processCHAnnouncement(Packet *packet);
    virtual void processJoinRequest(Packet *packet);
    virtual void processJoinReply(Packet *packet);

    // Timer handlers
    virtual void sendHelloPacket();
    virtual void performClusterElection();

    // WCA algorithm
    virtual double calculateWeight();
    virtual double calculateMobility();
    virtual double getBatteryLevel();
    virtual int getNodeDegree();

    // Helper functions
    virtual void updateNeighborInfo(const Ptr<const WcaPacket>& wcaPacket, const Ipv4Address& senderAddr);
    virtual void removeStaleNeighbors();
    virtual void sendPacket(Packet *packet, const Ipv4Address& destAddr);
    virtual void becomeClusterHead();
    virtual void joinCluster(const Ipv4Address& chAddress);

    // NetFilter hook
    virtual Result datagramPreRoutingHook(Packet *packet) override;
    virtual Result datagramForwardHook(Packet *packet) override { return ACCEPT; }
    virtual Result datagramPostRoutingHook(Packet *packet) override { return ACCEPT; }
    virtual Result datagramLocalInHook(Packet *packet) override { return ACCEPT; }
    virtual Result datagramLocalOutHook(Packet *packet) override { return ACCEPT; }

  public:
    Wca() {}
    virtual ~Wca();
};

} // namespace hwca

#endif
