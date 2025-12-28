#ifndef __HWCA_WCA_H
#define __HWCA_WCA_H

#include <omnetpp.h>
#include <map>
#include <set>

#include "inet/common/INETDefs.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/ipv4/Ipv4RoutingTable.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/power/contract/IEpEnergyStorage.h"
#include "inet/common/geometry/common/Coord.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "WcaPacket_m.h"
#include "WcaMetricsLogger.h"

namespace hwca {

using namespace omnetpp;
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
    bool hasAPConnectivity;
    double gatewayScore;

};
  enum class NetworkMode {
    DIRECT_AP,       // Direct connectivity to access point
    GATEWAY,         // Clusterhead with AP connectivity
    CLUSTER_MEMBER,  // Connected to server through a gateway
    DISCONNECTED     // No connectivity to server
};

class Wca : public cSimpleModule, public NetfilterBase::HookBase
{
  protected:
    double helloInterval;
    double clusterTimeout;
    double maxTransmissionPower;
    double degreeWeight;           // w1: weight for degree difference
    double distanceWeight;         // w2: weight for sum of distances
    double mobilityWeight;         // w3: weight for mobility
    double clusterHeadTimeWeight;  // w4: weight for cumulative CH time
    double apDistanceWeight;         // w5: weight for AP distance
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
    cMessage *statusReportTimer = nullptr;
    double statusReportInterval;
    Ipv4Address serverAddress;
    int statusSequenceNumber;

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
    std::vector<cOvalFigure*> apRangeCircles;  // Visual circles showing AP coverage

    // HWCA Infrastructure Support
    NetworkMode networkMode;
    double apSignalThreshold;
    double distanceToNearestAP;
    bool hasAPConnectivity;
    Ipv4Address myGateway;
    std::vector<Coord> apPositions;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void sendHelloPacket();
    void processHelloPacket(const Ptr<const WcaPacket>& wcaPacket);
    void performClusterElection();
    void becomeClusterHead();
    void stepDownFromClusterHead();
    void joinCluster(const Ipv4Address& chAddress);
    void findAndJoinBestCluster();
    void processCHAnnouncement(const Ptr<const WcaPacket>& wcaPacket);
    void processJoinRequest(const Ptr<const WcaPacket>& wcaPacket);
    void processJoinReply(const Ptr<const WcaPacket>& wcaPacket);
    void processWcaPacket(Packet *packet, const Ptr<const WcaPacket>& wcaPacket);

    double calculateWeight();
    double calculateMobility();
    double getSumOfDistances();
    double getCumulativeCHTime();
    int getNodeDegree();

    void updateNeighborInfo(const Ptr<const WcaPacket>& wcaPacket, const Ipv4Address& senderAddr);
    void removeStaleNeighbors();

    void sendPacket(Packet *packet, const Ipv4Address& destAddr);
    void forwardDataPacket(Packet *packet);

    // Visualization
    void initializeVisualization();
    void updateVisualization();
    void updateConnectionLines();
    void drawConnectionLine(const Ipv4Address& targetAddr, const char* color, int width);
    int getNodeIdFromAddress(const Ipv4Address& addr);
    void visualizeAPCoverage();

    // HWCA Mode Selection
    void updateNetworkMode();
    double getDistanceToNearestAP();
    bool checkAPConnectivity();
    Ipv4Address findBestGateway();
    const char* networkModeToString(NetworkMode mode);
    void parseAPPositions(const char* apPosStr);
    bool hasMembersOutsideAPRange();
    void sendGatewayAnnouncement();
    void processGatewayAnnouncement(const Ptr<const WcaPacket>& wcaPacket);
    void sendDataThroughGateway(Packet *packet, const Ipv4Address& finalDest);
    void processDataForward(Packet *packet, const Ptr<const WcaPacket>& wcaPacket);
    void sendStatusReport();
    void processStatusReport(const Ptr<const WcaPacket>& wcaPacket);
    void processServerBroadcast(const Ptr<const WcaPacket>& wcaPacket);

    void triggerGatewayElection();
    bool shouldBecomeGateway();
    double calculateGatewayScore();

    void sendGatewayDiscoveryRequest();
    void processGatewayDiscoveryRequest(const Ptr<const WcaPacket>& wcaPacket);
    void processGatewayDiscoveryReply(const Ptr<const WcaPacket>& wcaPacket);

    void checkGatewayHandover();
    void performGatewayHandover(const Ipv4Address& newGateway);
  public:
    virtual ~Wca();

    virtual Result datagramPreRoutingHook(Packet *datagram) override;
    virtual Result datagramForwardHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramPostRoutingHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalInHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalOutHook(Packet *datagram) override { return ACCEPT; }
};

} // namespace hwca

#endif