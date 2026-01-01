#ifndef __HWCA_SERVER_H
#define __HWCA_SERVER_H

#include <omnetpp.h>
#include <map>
#include <set>
#include <sys/stat.h>
#include <iomanip>
#include <fstream>
#include "inet/common/INETDefs.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/ipv4/Ipv4RoutingTable.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "WcaPacket_m.h"

namespace hwca {

using namespace omnetpp;
using namespace inet;

// Structure to track robot state
struct RobotState {
    Ipv4Address address;
    int nodeId;
    int networkMode;
    bool isClusterHead;
    Ipv4Address clusterHead;
    Ipv4Address gateway;
    double energyLevel;
    std::string taskInfo;
    int lastSequenceNumber;
    simtime_t lastReportTime;
    bool isConnected;
};

class HwcaServer : public cSimpleModule, public NetfilterBase::HookBase
{
  protected:
    // Parameters
    double broadcastInterval;
    double robotTimeoutThreshold;
    int expectedRobotCount;

    // State
    Ipv4Address myAddress;
    int broadcastSequenceNumber;
    std::map<Ipv4Address, RobotState> robotStates;
    std::set<Ipv4Address> connectedRobots;
    std::set<Ipv4Address> disconnectedRobots;

    // Timers
    cMessage *broadcastTimer = nullptr;
    cMessage *timeoutCheckTimer = nullptr;

    // Module references
    IInterfaceTable *interfaceTable = nullptr;
    IIpv4RoutingTable *routingTable = nullptr;
    NetworkInterface *interface80211 = nullptr;
    INetfilter *networkProtocol = nullptr;

    // Signals
    simsignal_t robotStatusReceivedSignal;
    simsignal_t robotDisconnectedSignal;
    simsignal_t connectedRobotCountSignal;

    std::ofstream serverCsvFile;
    std::ofstream serverLogFile;

    // Counters
    int totalStatusReportsReceived;
    int totalForwardedReportsReceived;
    int totalBroadcastsSent;

    // Mode distribution tracking
    std::map<int, int> modeDistribution;  // mode -> count at last check

    // Latency tracking (if timestamps are available)
    std::vector<double> reportLatencies;

    // Connection history
    std::vector<std::pair<simtime_t, int>> connectedCountHistory;
    std::vector<std::pair<simtime_t, int>> disconnectedCountHistory;

    void initializeMetrics();
    void logServerMetrics(simtime_t time);
    void finalizeServerMetrics();

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Message processing
    void processStatusReport(const Ptr<const WcaPacket>& wcaPacket);
    void processWcaPacket(Packet *packet, const Ptr<const WcaPacket>& wcaPacket);

    // Server actions
    void sendBroadcast(const char* command = "");
    void checkRobotTimeouts();
    void updateRobotState(const Ptr<const WcaPacket>& wcaPacket);
    void logFleetStatus();

    // Helpers
    void sendPacket(Packet *packet, const Ipv4Address& destAddr);
    const char* networkModeToString(int mode);

  public:
    virtual ~HwcaServer();

    // Netfilter hooks
    virtual Result datagramPreRoutingHook(Packet *datagram) override;
    virtual Result datagramForwardHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramPostRoutingHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalInHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalOutHook(Packet *datagram) override { return ACCEPT; }
};

} // namespace hwca

#endif