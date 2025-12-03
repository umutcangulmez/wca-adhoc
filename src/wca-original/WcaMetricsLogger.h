#ifndef __HWCA_WCA_METRICS_LOGGER_H
#define __HWCA_WCA_METRICS_LOGGER_H

#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <omnetpp.h>

namespace hwca {

using namespace omnetpp;

/**
 * Metrics Logger for WCA Simulation
 * Tracks:
 * 1. Energy consumption over time
 * 2. Cluster head duration over time
 * 3. Cluster head selection/reselection count
 * 4. Sent UDP packet count
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

    int getSentUdpPacketCount() const { return sentUdpPacketCount; }
    int getCHSelectionCount() const { return chSelectionCount; }
    double getTotalCHDuration() const { return totalCHDuration; }
    double getEnergyConsumed() const { return initialEnergy - lastLoggedEnergy; }
};

} // namespace hwca

#endif // __HWCA_WCA_METRICS_LOGGER_H
