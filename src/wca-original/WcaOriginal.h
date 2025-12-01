#ifndef __INET_WCA_H
#define __INET_WCA_H

#include "inet/common/INETDefs.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/ipv4/IIpv4RoutingTable.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/power/contract/IEpEnergyStorage.h"
#include "inet/common/geometry/common/Coord.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "WcaPacket_m.h"
#include "WcaMetricsLogger.h"

namespace hwca {

using namespace inet;

struct NeighborInfo {
    Ipv4Address address;
    double weight;
    int nodeDegree;
    double transmissionPower;
    double mobility;
    double batteryPower;
    bool isClusterHead;
    Ipv4Address clusterHeadAddress;
    simtime_t lastSeen;
    Coord position;
    Coord previousPosition;

    // Constructor with default values
    NeighborInfo() : weight(0), nodeDegree(0), transmissionPower(0),
                     mobility(0), batteryPower(0), isClusterHead(false),
                     lastSeen(0) {}
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
    double degreeWeight;           // w1: weight for degree difference
    double distanceWeight;         // w2: weight for sum of distances
    double mobilityWeight;         // w3: weight for mobility
    double clusterHeadTimeWeight;  // w4: weight for cumulative CH time
    double radioRange;
    int idealDegree;               // Ideal number of neighbors

    int myNodeId;
    Ipv4Address myAddress;
    double myWeight;
    bool isClusterHead;
    Ipv4Address myClusterHead;

    // Cumulative CH Time Tracking
    simtime_t cumulativeCHTime;
    simtime_t lastCHStartTime;

    std::map<Ipv4Address, NeighborInfo> neighbors;
    std::set<Ipv4Address> clusterMembers;

    cMessage *helloTimer = nullptr;
    cMessage *clusterTimer = nullptr;
    cMessage *metricTimer = nullptr;

    IInterfaceTable *interfaceTable = nullptr;
    IIpv4RoutingTable *routingTable = nullptr;
    NetworkInterface *interface80211 = nullptr;
    IMobility *mobility = nullptr;
    power::IEpEnergyStorage *energyStorage = nullptr;
    INetfilter *networkProtocol = nullptr;

    Coord previousPosition;
    simtime_t lastMobilityUpdate;

    WCAMetricsLogger *metricsLogger = nullptr;
    int packetIdCounter;

    simsignal_t clusterHeadChangedSignal;
    simsignal_t weightSignal;
    simsignal_t neighborCountSignal;

    // Visualization
    cCanvas *canvas = nullptr;
    cOvalFigure *clusterMarker = nullptr;
    cTextFigure *weightText = nullptr;
    cTextFigure *statusText = nullptr;
    std::map<Ipv4Address, cLineFigure*> connectionLines;

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

    // Visualization
    void initializeVisualization();
    void updateVisualization();
    void updateConnectionLines();
    void drawConnectionLine(const Ipv4Address& targetAddr, const char* color, int width);
    int getNodeIdFromAddress(const Ipv4Address& addr);

  public:
    virtual ~Wca();
};

} // namespace hwca

#endif
