#include "WcaMetricsLogger.h"
#include <iomanip>
#include <numeric>

WCAMetricsLogger::WCAMetricsLogger() {
    totalPacketsSent = 0;
    totalPacketsReceived = 0;
    totalPacketsDropped = 0;
    totalRoutingOverhead = 0;
    totalEnergyConsumed = 0.0;
    clusterHeadChanges = 0;
    totalClusterFormed = 0;
    simulationStartTime = 0;
    lastLogTime = 0;
}

WCAMetricsLogger::~WCAMetricsLogger() {
    if (logFile.is_open()) logFile.close();
    if (csvFile.is_open()) csvFile.close();
}

void WCAMetricsLogger::initialize(const char* logFileName, const char* csvFileName) {
    logFile.open(logFileName, std::ios::out);
    csvFile.open(csvFileName, std::ios::out);

    if (!logFile.is_open() || !csvFile.is_open()) {
        EV << "ERROR: Could not open log files!" << endl;
        return;
    }

    // Write CSV header
    csvFile << "Time,PacketsSent,PacketsReceived,PacketsDropped,PDR,"
            << "AvgDelay,AvgHopCount,Throughput,RoutingOverhead,"
            << "EnergyConsumed,NumClusters\n";

    logFile << "=== WCA Protocol Performance Log ===" << endl;
    logFile << "Simulation Started at: " << simTime() << endl << endl;

    simulationStartTime = simTime();
}

void WCAMetricsLogger::logPacketSent(int packetId, int sourceNode, int destNode, simtime_t timestamp) {
    totalPacketsSent++;

    logFile << "[" << timestamp << "] PACKET_SENT: ID=" << packetId
            << " Source=" << sourceNode << " Dest=" << destNode << endl;
}

void WCAMetricsLogger::logPacketReceived(int packetId, int destNode, simtime_t timestamp, int hopCount) {
    totalPacketsReceived++;

    // Calculate delay if we have send time
    if (packetDelays.find(packetId) != packetDelays.end()) {
        double delay = (timestamp - packetDelays[packetId]).dbl();
        packetDelays[packetId] = delay;
    }

    hopCounts[packetId] = hopCount;

    logFile << "[" << timestamp << "] PACKET_RECEIVED: ID=" << packetId
            << " Dest=" << destNode << " Hops=" << hopCount << endl;
}

void WCAMetricsLogger::logPacketDropped(int packetId, int nodeId, const char* reason, simtime_t timestamp) {
    totalPacketsDropped++;

    logFile << "[" << timestamp << "] PACKET_DROPPED: ID=" << packetId
            << " Node=" << nodeId << " Reason=" << reason << endl;
}

void WCAMetricsLogger::logRoutingOverhead(int controlPackets) {
    totalRoutingOverhead += controlPackets;

    logFile << "[" << simTime() << "] ROUTING_OVERHEAD: "
            << controlPackets << " control packets" << endl;
}

void WCAMetricsLogger::logClusterFormation(int numClusters, std::vector<int> clusterHeads) {
    totalClusterFormed = numClusters;
    clusterHeadChanges++;

    logFile << "[" << simTime() << "] CLUSTER_FORMATION: "
            << numClusters << " clusters formed" << endl;
    logFile << "Cluster Heads: ";
    for (int ch : clusterHeads) {
        logFile << ch << " ";
    }
    logFile << endl;
}

void WCAMetricsLogger::logEnergyConsumption(int nodeId, double energy) {
    totalEnergyConsumed += energy;

    logFile << "[" << simTime() << "] ENERGY: Node=" << nodeId
            << " Consumed=" << energy << " J" << endl;
}

void WCAMetricsLogger::logRoutePath(int packetId, std::vector<int> path) {
    routePaths[packetId] = path;

    logFile << "[" << simTime() << "] ROUTE_PATH for Packet " << packetId << ": ";
    for (size_t i = 0; i < path.size(); i++) {
        logFile << path[i];
        if (i < path.size() - 1) logFile << " -> ";
    }
    logFile << endl;
}

double WCAMetricsLogger::getAverageDelay() {
    if (packetDelays.empty()) return 0.0;

    double sum = 0.0;
    for (auto& pair : packetDelays) {
        sum += pair.second;
    }
    return sum / packetDelays.size();
}

double WCAMetricsLogger::getPacketDeliveryRatio() {
    if (totalPacketsSent == 0) return 0.0;
    return (double)totalPacketsReceived / totalPacketsSent;
}

double WCAMetricsLogger::getAverageHopCount() {
    if (hopCounts.empty()) return 0.0;

    double sum = 0.0;
    for (auto& pair : hopCounts) {
        sum += pair.second;
    }
    return sum / hopCounts.size();
}

double WCAMetricsLogger::getThroughput(simtime_t duration) {
    if (duration.dbl() == 0) return 0.0;
    // Assuming average packet size of 512 bytes
    return (totalPacketsReceived * 512 * 8) / duration.dbl(); // bits per second
}

double WCAMetricsLogger::getRoutingOverheadRatio() {
    int totalPackets = totalPacketsSent + totalRoutingOverhead;
    if (totalPackets == 0) return 0.0;
    return (double)totalRoutingOverhead / totalPackets;
}

void WCAMetricsLogger::calculateAndLogMetrics(simtime_t currentTime) {
    simtime_t duration = currentTime - simulationStartTime;

    logFile << "\n=== Metrics Summary at " << currentTime << " ===" << endl;
    logFile << "Packets Sent: " << totalPacketsSent << endl;
    logFile << "Packets Received: " << totalPacketsReceived << endl;
    logFile << "Packets Dropped: " << totalPacketsDropped << endl;
    logFile << "Packet Delivery Ratio: " << std::fixed << std::setprecision(4)
            << getPacketDeliveryRatio() * 100 << "%" << endl;
    logFile << "Average Delay: " << getAverageDelay() << " s" << endl;
    logFile << "Average Hop Count: " << std::setprecision(2) << getAverageHopCount() << endl;
    logFile << "Throughput: " << getThroughput(duration) << " bps" << endl;
    logFile << "Routing Overhead: " << getRoutingOverheadRatio() * 100 << "%" << endl;
    logFile << "Total Energy Consumed: " << totalEnergyConsumed << " J" << endl;
    logFile << "Clusters Formed: " << totalClusterFormed << endl;
    logFile << "Cluster Head Changes: " << clusterHeadChanges << endl << endl;

    // Write to CSV
    csvFile << currentTime << ","
            << totalPacketsSent << ","
            << totalPacketsReceived << ","
            << totalPacketsDropped << ","
            << getPacketDeliveryRatio() << ","
            << getAverageDelay() << ","
            << getAverageHopCount() << ","
            << getThroughput(duration) << ","
            << getRoutingOverheadRatio() << ","
            << totalEnergyConsumed << ","
            << totalClusterFormed << "\n";

    csvFile.flush();
    lastLogTime = currentTime;
}

void WCAMetricsLogger::finalizeAndClose() {
    logFile << "\n=== FINAL STATISTICS ===" << endl;
    calculateAndLogMetrics(simTime());

    logFile << "\nSimulation completed successfully." << endl;
    logFile.close();
    csvFile.close();
}
