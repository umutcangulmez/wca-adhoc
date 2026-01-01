#ifndef __HWCA_WCA_METRICS_LOGGER_H
#define __HWCA_WCA_METRICS_LOGGER_H

#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <omnetpp.h>

namespace hwca {

using namespace omnetpp;

// Network mode enum for metrics
enum class MetricNetworkMode {
    DIRECT_AP = 0,
    GATEWAY = 1,
    CLUSTER_MEMBER = 2,
    DISCONNECTED = 3
};

/**
 * Metrics Logger for WCA/HWCA Simulation
 * Tracks:
 * 1. Energy consumption over time
 * 2. Cluster head duration over time
 * 3. Cluster head selection/reselection count
 * 4. Sent UDP packet count
 * 5. HWCA-specific: Network mode, connectivity, gateway metrics
 */
class WCAMetricsLogger
{
  private:
    std::ofstream logFile;
    std::ofstream csvFile;

    int nodeId;
    std::string nodeIdStr;

    // Energy
    double initialEnergy;
    double lastLoggedEnergy;
    std::vector<std::pair<simtime_t, double>> energyOverTime;

    // Cluster head
    bool isCurrentlyCH;
    simtime_t chStartTime;
    double totalCHDuration;
    std::vector<std::pair<simtime_t, double>> chDurationOverTime;

    // CH selection
    int chSelectionCount;      // How many times this node became CH
    int chReselectionCount;    // How many times CH changed
    std::vector<std::pair<simtime_t, int>> chSelectionsOverTime;

    // Packet
    int sentUdpPacketCount;
    int sentWcaPacketCount;
    int receivedPacketCount;
    int droppedPacketCount;
    std::vector<std::pair<simtime_t, int>> sentPacketsOverTime;

    // Routing overhead
    int routingOverheadCount;

    // Network mode tracking
    MetricNetworkMode currentMode;
    simtime_t modeStartTime;
    bool modeInitialized;

    double totalDirectAPTime;
    double totalGatewayTime;
    double totalClusterMemberTime;
    double totalDisconnectedTime;

    // Disconnection tracking
    int disconnectionCount;
    simtime_t lastDisconnectTime;
    std::vector<double> disconnectionDurations;

    // Gateway metrics
    int gatewayElectionCount;
    int gatewayHandoverCount;
    double totalGatewayServingTime;  // Time spent as gateway serving others
    int membersServedAsGateway;      // Total members served while gateway

    // Status report metrics
    int statusReportsSent;
    int statusReportsDelivered;
    int statusReportsForwarded;      // Forwarded through gateway
    std::vector<double> statusReportLatencies;

    // Connectivity metrics
    int hopsToServer;
    std::vector<std::pair<simtime_t, int>> hopsOverTime;

    // Mode transition tracking
    std::vector<std::pair<simtime_t, MetricNetworkMode>> modeTransitions;

  public:
    WCAMetricsLogger();
    ~WCAMetricsLogger();

    void initialize(const char* logFilePath, const char* csvFilePath);

    void setNodeId(int id);

    void setInitialEnergy(double energy);

    void logEnergy(double currentEnergy, simtime_t time);

    void logEnergyConsumption(int nodeId, double consumed);

    void logBecomeCH(simtime_t time);

    void logStopCH(simtime_t time);

    void logCHReselection(simtime_t time);

    void logClusterFormation(int numClusters, std::vector<int>& clusterHeads);

    void logUdpPacketSent(simtime_t time);

    void logWcaPacketSent(simtime_t time);

    void logPacketSent(int packetId, int nodeId, uint32_t destAddr, simtime_t time);

    void logPacketReceived(int packetId, int nodeId, simtime_t time, int hopCount);

    void logPacketDropped(int packetId, int nodeId, const char* reason, simtime_t time);

    void logRoutingOverhead(int count);

    void calculateAndLogMetrics(simtime_t time);

    void finalizeAndClose();

    // Network mode
    void logNetworkModeChange(MetricNetworkMode newMode, simtime_t time);
    void logDisconnection(simtime_t time);
    void logReconnection(simtime_t time);

    // Gateway
    void logGatewayElection(simtime_t time);
    void logGatewayHandover(simtime_t time);
    void logGatewayServing(int memberCount, simtime_t time);

    // Status reports
    void logStatusReportSent(simtime_t time);
    void logStatusReportDelivered(simtime_t sendTime, simtime_t receiveTime);
    void logStatusReportForwarded(simtime_t time);

    // Connectivity
    void logHopsToServer(int hops, simtime_t time);

    // Getters for existing metrics
    int getSentUdpPacketCount() const { return sentUdpPacketCount; }
    int getCHSelectionCount() const { return chSelectionCount; }
    double getTotalCHDuration() const { return totalCHDuration; }
    double getEnergyConsumed() const { return initialEnergy - lastLoggedEnergy; }

    // Getters for HWCA metrics
    double getTotalDisconnectedTime() const { return totalDisconnectedTime; }
    int getDisconnectionCount() const { return disconnectionCount; }
    double getTotalGatewayTime() const { return totalGatewayTime; }
    int getGatewayElectionCount() const { return gatewayElectionCount; }
    int getStatusReportsSent() const { return statusReportsSent; }
    int getStatusReportsDelivered() const { return statusReportsDelivered; }
    double getAvgStatusReportLatency() const;
    double getConnectivityRatio(simtime_t totalTime) const;

    const char* modeToString(MetricNetworkMode mode) const;
};

} // namespace hwca

#endif // __HWCA_WCA_METRICS_LOGGER_H