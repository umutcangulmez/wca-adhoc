#include "WcaMetricsLogger.h"
#include <iomanip>
#include <sstream>
#include <ctime>
#include <sys/stat.h>
#include <numeric>
#include <cmath>

namespace hwca {

WCAMetricsLogger::WCAMetricsLogger()
    : nodeId(-1),
      initialEnergy(0),
      lastLoggedEnergy(0),
      isCurrentlyCH(false),
      chStartTime(0),
      totalCHDuration(0),
      chSelectionCount(0),
      chReselectionCount(0),
      sentUdpPacketCount(0),
      sentWcaPacketCount(0),
      receivedPacketCount(0),
      droppedPacketCount(0),
      routingOverheadCount(0),
      // HWCA-specific initialization
      currentMode(MetricNetworkMode::DISCONNECTED),
      modeStartTime(0),
      modeInitialized(false),
      totalDirectAPTime(0),
      totalGatewayTime(0),
      totalClusterMemberTime(0),
      totalDisconnectedTime(0),
      disconnectionCount(0),
      lastDisconnectTime(0),
      gatewayElectionCount(0),
      gatewayHandoverCount(0),
      totalGatewayServingTime(0),
      membersServedAsGateway(0),
      statusReportsSent(0),
      statusReportsDelivered(0),
      statusReportsForwarded(0),
      hopsToServer(0)
{
}

WCAMetricsLogger::~WCAMetricsLogger()
{
    if (logFile.is_open()) {
        logFile.close();
    }
    if (csvFile.is_open()) {
        csvFile.close();
    }
}

void WCAMetricsLogger::initialize(const char* logFilePath, const char* csvFilePath)
{
    // Create directory if it doesn't exist
    mkdir("results", 0755);

    // Open log file
    logFile.open(logFilePath, std::ios::out | std::ios::trunc);
    if (logFile.is_open()) {
        logFile << "HWCA Simulation Metrics Log\n";
        logFile << "===========================\n\n";
    }

    // Open csv file
    csvFile.open(csvFilePath, std::ios::out | std::ios::trunc);
    if (csvFile.is_open()) {
        csvFile << "time,node_id,energy_consumed,energy_remaining,is_ch,ch_duration_cumulative,"
                << "ch_selections_cumulative,ch_reselections_cumulative,"
                << "udp_packets_sent,wca_packets_sent,packets_received,packets_dropped,"
                << "routing_overhead,"
                // HWCA columns
                << "network_mode,disconnected_time,disconnection_count,"
                << "gateway_time,gateway_elections,gateway_handovers,"
                << "status_reports_sent,status_reports_delivered,status_reports_forwarded,"
                << "hops_to_server,connectivity_ratio\n";
    }
}

void WCAMetricsLogger::setNodeId(int id)
{
    nodeId = id;
    nodeIdStr = std::to_string(id);
}

void WCAMetricsLogger::setInitialEnergy(double energy)
{
    initialEnergy = energy;
    lastLoggedEnergy = energy;
}

void WCAMetricsLogger::logEnergy(double currentEnergy, simtime_t time)
{
    double consumed = initialEnergy - currentEnergy;
    lastLoggedEnergy = currentEnergy;

    energyOverTime.push_back({time, consumed});

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "Node " << nodeId << " Energy: "
                << std::setprecision(2) << currentEnergy << "J remaining, "
                << consumed << "J consumed\n";
    }
}

void WCAMetricsLogger::logEnergyConsumption(int nodeId, double consumed)
{
    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << simTime().dbl() << "s] "
                << "Node " << nodeId << " Total energy consumed: "
                << std::setprecision(4) << consumed << "J\n";
    }
}

void WCAMetricsLogger::logBecomeCH(simtime_t time)
{
    if (!isCurrentlyCH) {
        isCurrentlyCH = true;
        chStartTime = time;
        chSelectionCount++;

        chSelectionsOverTime.push_back({time, chSelectionCount});

        if (logFile.is_open()) {
            logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                    << "*** Node " << nodeId << " BECAME CLUSTER HEAD "
                    << "(selection #" << chSelectionCount << ") ***\n";
        }
    }
}

void WCAMetricsLogger::logStopCH(simtime_t time)
{
    if (isCurrentlyCH) {
        isCurrentlyCH = false;
        double duration = (time - chStartTime).dbl();
        totalCHDuration += duration;

        chDurationOverTime.push_back({time, totalCHDuration});

        if (logFile.is_open()) {
            logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                    << "*** Node " << nodeId << " STOPPED being CH "
                    << "(was CH for " << std::setprecision(2) << duration << "s, "
                    << "total CH time: " << totalCHDuration << "s) ***\n";
        }
    }
}

void WCAMetricsLogger::logCHReselection(simtime_t time)
{
    chReselectionCount++;

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "CH Reselection triggered (total: " << chReselectionCount << ")\n";
    }
}

void WCAMetricsLogger::logClusterFormation(int numClusters, std::vector<int>& clusterHeads)
{
    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << simTime().dbl() << "s] "
                << "Cluster formation: " << numClusters << " clusters, CHs: [";
        for (size_t i = 0; i < clusterHeads.size(); i++) {
            logFile << clusterHeads[i];
            if (i < clusterHeads.size() - 1) logFile << ", ";
        }
        logFile << "]\n";
    }
}

void WCAMetricsLogger::logUdpPacketSent(simtime_t time)
{
    sentUdpPacketCount++;
    sentPacketsOverTime.push_back({time, sentUdpPacketCount});

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "Node " << nodeId << " sent UDP packet #" << sentUdpPacketCount << "\n";
    }
}

void WCAMetricsLogger::logWcaPacketSent(simtime_t time)
{
    sentWcaPacketCount++;
}

void WCAMetricsLogger::logPacketSent(int packetId, int nodeId, uint32_t destAddr, simtime_t time)
{
    sentWcaPacketCount++;
}

void WCAMetricsLogger::logPacketReceived(int packetId, int nodeId, simtime_t time, int hopCount)
{
    receivedPacketCount++;

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "Node " << nodeId << " received packet #" << packetId
                << " (hops: " << hopCount << ")\n";
    }
}

void WCAMetricsLogger::logPacketDropped(int packetId, int nodeId, const char* reason, simtime_t time)
{
    droppedPacketCount++;

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "Node " << nodeId << " DROPPED packet #" << packetId
                << " (reason: " << reason << ")\n";
    }
}

void WCAMetricsLogger::logRoutingOverhead(int count)
{
    routingOverheadCount += count;
}


void WCAMetricsLogger::logNetworkModeChange(MetricNetworkMode newMode, simtime_t time)
{
    // Skip duration calculation on first call
    if (modeInitialized) {
        double duration = (time - modeStartTime).dbl();

        if (duration > 0) {
            switch (currentMode) {
                case MetricNetworkMode::DIRECT_AP:
                    totalDirectAPTime += duration;
                    break;
                case MetricNetworkMode::GATEWAY:
                    totalGatewayTime += duration;
                    break;
                case MetricNetworkMode::CLUSTER_MEMBER:
                    totalClusterMemberTime += duration;
                    break;
                case MetricNetworkMode::DISCONNECTED:
                    totalDisconnectedTime += duration;
                    disconnectionDurations.push_back(duration);
                    break;
            }
        }
    }

    modeTransitions.push_back({time, newMode});

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "Node " << nodeId << " mode: " << modeToString(currentMode)
                << " -> " << modeToString(newMode) << "\n";
    }

    currentMode = newMode;
    modeStartTime = time;
    modeInitialized = true;
}

void WCAMetricsLogger::logDisconnection(simtime_t time)
{
    disconnectionCount++;
    lastDisconnectTime = time;

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "*** Node " << nodeId << " DISCONNECTED (count: "
                << disconnectionCount << ") ***\n";
    }
}

void WCAMetricsLogger::logReconnection(simtime_t time)
{
    double disconnectDuration = (time - lastDisconnectTime).dbl();

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "*** Node " << nodeId << " RECONNECTED after "
                << disconnectDuration << "s ***\n";
    }
}

void WCAMetricsLogger::logGatewayElection(simtime_t time)
{
    gatewayElectionCount++;

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "Node " << nodeId << " elected as GATEWAY (election #"
                << gatewayElectionCount << ")\n";
    }
}

void WCAMetricsLogger::logGatewayHandover(simtime_t time)
{
    gatewayHandoverCount++;

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "Node " << nodeId << " gateway handover (handover #"
                << gatewayHandoverCount << ")\n";
    }
}

void WCAMetricsLogger::logGatewayServing(int memberCount, simtime_t time)
{
    membersServedAsGateway += memberCount;

    if (logFile.is_open()) {
        logFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                << "Node " << nodeId << " serving " << memberCount
                << " members as gateway\n";
    }
}

void WCAMetricsLogger::logStatusReportSent(simtime_t time)
{
    statusReportsSent++;
}

void WCAMetricsLogger::logStatusReportDelivered(simtime_t sendTime, simtime_t receiveTime)
{
    statusReportsDelivered++;
    double latency = (receiveTime - sendTime).dbl();
    statusReportLatencies.push_back(latency);
}

void WCAMetricsLogger::logStatusReportForwarded(simtime_t time)
{
    statusReportsForwarded++;
}

void WCAMetricsLogger::logHopsToServer(int hops, simtime_t time)
{
    hopsToServer = hops;
    hopsOverTime.push_back({time, hops});
}

double WCAMetricsLogger::getAvgStatusReportLatency() const
{
    if (statusReportLatencies.empty()) return 0.0;
    double sum = std::accumulate(statusReportLatencies.begin(),
                                  statusReportLatencies.end(), 0.0);
    return sum / statusReportLatencies.size();
}

double WCAMetricsLogger::getConnectivityRatio(simtime_t totalTime) const
{
    if (totalTime.dbl() <= 0) return 100.0;
    double connectedTime = totalTime.dbl() - totalDisconnectedTime;
    return (connectedTime / totalTime.dbl()) * 100.0;
}

const char* WCAMetricsLogger::modeToString(MetricNetworkMode mode) const
{
    switch (mode) {
        case MetricNetworkMode::DIRECT_AP: return "DIRECT_AP";
        case MetricNetworkMode::GATEWAY: return "GATEWAY";
        case MetricNetworkMode::CLUSTER_MEMBER: return "CLUSTER_MEMBER";
        case MetricNetworkMode::DISCONNECTED: return "DISCONNECTED";
        default: return "UNKNOWN";
    }
}

void WCAMetricsLogger::calculateAndLogMetrics(simtime_t time)
{
    // Calculate current CH duration if still CH
    double currentCHDuration = totalCHDuration;
    if (isCurrentlyCH) {
        currentCHDuration += (time - chStartTime).dbl();
    }

    // Power consumption values (in Watts):
    // - Idle/listening: 0.5 W (radio in receive mode, listening for packets)
    // - Transmitting: 1.5 W
    // - Receiving: 1.0 W
    // - CH processing overhead: 0.2 W (additional CPU for cluster management)
    // Packet transmission/reception duration: ~2ms per packet (512 bytes at 2Mbps)

    double currentModeTime = (time - modeStartTime).dbl();
    double tempDirectAP = totalDirectAPTime;
    double tempGateway = totalGatewayTime;
    double tempClusterMember = totalClusterMemberTime;
    double tempDisconnected = totalDisconnectedTime;

    switch (currentMode) {
        case MetricNetworkMode::DIRECT_AP: tempDirectAP += currentModeTime; break;
        case MetricNetworkMode::GATEWAY: tempGateway += currentModeTime; break;
        case MetricNetworkMode::CLUSTER_MEMBER: tempClusterMember += currentModeTime; break;
        case MetricNetworkMode::DISCONNECTED: tempDisconnected += currentModeTime; break;
    }

    // Energy calculation (same as before)
    double idlePower = 0.5;
    double txPower = 1.5;
    double rxPower = 1.0;
    double chOverheadPower = 2;
    double gatewayOverheadPower = 1.5;  // Gateway has extra overhead
    double packetDuration = 0.002;

    double timeSeconds = time.dbl();

    // Calculate time spent in each state
    int totalTxPackets = sentUdpPacketCount + sentWcaPacketCount;
    double txTime = totalTxPackets * packetDuration;
    double rxTime = receivedPacketCount * packetDuration;
    double idleTime = timeSeconds - txTime - rxTime;  // Rest of time is idle
    if (idleTime < 0) idleTime = 0;

    // Calculate energy components
    double idleEnergy = idlePower * idleTime;
    double txEnergy = txPower * txTime;
    double rxEnergy = rxPower * rxTime;
    double chEnergy = chOverheadPower * currentCHDuration;
    double gatewayEnergy = gatewayOverheadPower * tempGateway;

    double energyConsumed = idleEnergy + txEnergy + rxEnergy + chEnergy + gatewayEnergy;

    // Store for the energy over time tracking
    energyOverTime.push_back({time, energyConsumed});
    lastLoggedEnergy = initialEnergy - energyConsumed;

    // Connectivity ratio
    double connectivityRatio = getConnectivityRatio(time);

    if (csvFile.is_open()) {
        csvFile << std::fixed << std::setprecision(3)
                << time.dbl() << ","                    // time
                << nodeId << ","                        // node_id
                << std::setprecision(4)
                << energyConsumed << ","                // energy_consumed
                << lastLoggedEnergy << ","              // energy_remaining
                << (isCurrentlyCH ? 1 : 0) << ","       // is_ch
                << std::setprecision(2)
                << currentCHDuration << ","             // ch_duration_cumulative
                << chSelectionCount << ","              // ch_selections_cumulative
                << chReselectionCount << ","            // ch_reselections_cumulative
                << sentUdpPacketCount << ","            // udp_packets_sent
                << sentWcaPacketCount << ","            // wca_packets_sent
                << receivedPacketCount << ","           // packets_received
                << droppedPacketCount << ","            // packets_dropped
                << routingOverheadCount << ","          // routing_overhead
                // HWCA columns
                << static_cast<int>(currentMode) << "," // network_mode
                << tempDisconnected << ","              // disconnected_time
                << disconnectionCount << ","            // disconnection_count
                << tempGateway << ","                   // gateway_time
                << gatewayElectionCount << ","          // gateway_elections
                << gatewayHandoverCount << ","          // gateway_handovers
                << statusReportsSent << ","             // status_reports_sent
                << statusReportsDelivered << ","        // status_reports_delivered
                << statusReportsForwarded << ","        // status_reports_forwarded
                << hopsToServer << ","                  // hops_to_server
                << std::setprecision(1)
                << connectivityRatio                    // connectivity_ratio
                << "\n";
        csvFile.flush();
    }

    // Write summary to log
    if (logFile.is_open()) {
        logFile << "\n--- Metrics at t=" << std::fixed << std::setprecision(2)
                << time.dbl() << "s ---\n";
        logFile << "  Energy consumed: " << std::setprecision(2) << energyConsumed << " J\n";
        logFile << "  Is CH: " << (isCurrentlyCH ? "YES" : "NO") << "\n";
        logFile << "  Network Mode: " << modeToString(currentMode) << "\n";
        logFile << "  Connectivity Ratio: " << std::setprecision(1) << connectivityRatio << "%\n";
        logFile << "  Disconnection Count: " << disconnectionCount << "\n";
        logFile << "  Gateway Elections: " << gatewayElectionCount << "\n";
        logFile << "  Status Reports: sent=" << statusReportsSent
                << ", delivered=" << statusReportsDelivered
                << ", forwarded=" << statusReportsForwarded << "\n";
        logFile << "-----------------------------------\n\n";
        logFile.flush();
    }
}

void WCAMetricsLogger::finalizeAndClose()
{
    simtime_t endTime = simTime();

    // Finalize CH duration
    if (isCurrentlyCH) {
        double duration = (endTime - chStartTime).dbl();
        totalCHDuration += duration;
    }

    // Finalize mode duration
    double duration = (endTime - modeStartTime).dbl();
    switch (currentMode) {
        case MetricNetworkMode::DIRECT_AP: totalDirectAPTime += duration; break;
        case MetricNetworkMode::GATEWAY: totalGatewayTime += duration; break;
        case MetricNetworkMode::CLUSTER_MEMBER: totalClusterMemberTime += duration; break;
        case MetricNetworkMode::DISCONNECTED: totalDisconnectedTime += duration; break;
    }

    // Energy calculation
    double idlePower = 0.5;
    double txPower = 1.5;
    double rxPower = 1.0;
    double chOverheadPower = 0.2;
    double gatewayOverheadPower = 0.15;
    double packetDuration = 0.002;

    double timeSeconds = endTime.dbl();
    int totalTxPackets = sentUdpPacketCount + sentWcaPacketCount;
    double txTime = totalTxPackets * packetDuration;
    double rxTime = receivedPacketCount * packetDuration;
    double idleTime = timeSeconds - txTime - rxTime;
    if (idleTime < 0) idleTime = 0;

    double idleEnergy = idlePower * idleTime;
    double txEnergy = txPower * txTime;
    double rxEnergy = rxPower * rxTime;
    double chEnergy = chOverheadPower * totalCHDuration;
    double gatewayEnergy = gatewayOverheadPower * totalGatewayTime;

    double energyConsumed = idleEnergy + txEnergy + rxEnergy + chEnergy + gatewayEnergy;
    lastLoggedEnergy = initialEnergy - energyConsumed;

    double connectivityRatio = getConnectivityRatio(endTime);
    double avgLatency = getAvgStatusReportLatency();

    if (logFile.is_open()) {
        logFile << "\n=========================================\n";
        logFile << "FINAL SUMMARY - Node " << nodeId << "\n";
        logFile << "=========================================\n";
        logFile << "Simulation duration: " << std::fixed << std::setprecision(2)
                << endTime.dbl() << " s\n\n";

        logFile << "=== ENERGY ===\n";
        logFile << "  Total consumed: " << std::setprecision(4) << energyConsumed << " J\n";
        logFile << "    - Idle: " << idleEnergy << " J\n";
        logFile << "    - TX: " << txEnergy << " J\n";
        logFile << "    - RX: " << rxEnergy << " J\n";
        logFile << "    - CH overhead: " << chEnergy << " J\n";
        logFile << "    - Gateway overhead: " << gatewayEnergy << " J\n";
        if (timeSeconds > 0) {
            logFile << "  Average power: " << std::setprecision(3)
                    << (energyConsumed / timeSeconds) << " W\n";
        }

        logFile << "\n=== CLUSTER HEAD ===\n";
        logFile << "  Times became CH: " << chSelectionCount << "\n";
        logFile << "  Total CH duration: " << std::setprecision(2) << totalCHDuration << " s\n";
        if (endTime.dbl() > 0) {
            logFile << "  CH time percentage: " << std::setprecision(1)
                    << (totalCHDuration / endTime.dbl() * 100) << "%\n";
        }

        logFile << "\n=== HWCA NETWORK MODE ===\n";
        logFile << "  Final mode: " << modeToString(currentMode) << "\n";
        logFile << "  Time in DIRECT_AP: " << std::setprecision(2) << totalDirectAPTime << " s ("
                << std::setprecision(1) << (totalDirectAPTime / endTime.dbl() * 100) << "%)\n";
        logFile << "  Time in GATEWAY: " << totalGatewayTime << " s ("
                << (totalGatewayTime / endTime.dbl() * 100) << "%)\n";
        logFile << "  Time in CLUSTER_MEMBER: " << totalClusterMemberTime << " s ("
                << (totalClusterMemberTime / endTime.dbl() * 100) << "%)\n";
        logFile << "  Time in DISCONNECTED: " << totalDisconnectedTime << " s ("
                << (totalDisconnectedTime / endTime.dbl() * 100) << "%)\n";

        logFile << "\n=== CONNECTIVITY ===\n";
        logFile << "  Connectivity Ratio: " << std::setprecision(1) << connectivityRatio << "%\n";
        logFile << "  Disconnection Count: " << disconnectionCount << "\n";
        if (!disconnectionDurations.empty()) {
            double avgDisconnect = std::accumulate(disconnectionDurations.begin(),
                                                    disconnectionDurations.end(), 0.0)
                                   / disconnectionDurations.size();
            logFile << "  Avg Disconnection Duration: " << std::setprecision(2)
                    << avgDisconnect << " s\n";
        }

        logFile << "\n=== GATEWAY ===\n";
        logFile << "  Gateway Elections: " << gatewayElectionCount << "\n";
        logFile << "  Gateway Handovers: " << gatewayHandoverCount << "\n";
        logFile << "  Total Gateway Serving Time: " << std::setprecision(2)
                << totalGatewayTime << " s\n";

        logFile << "\n=== STATUS REPORTS ===\n";
        logFile << "  Sent: " << statusReportsSent << "\n";
        logFile << "  Delivered: " << statusReportsDelivered << "\n";
        logFile << "  Forwarded (via gateway): " << statusReportsForwarded << "\n";
        if (statusReportsSent > 0) {
            logFile << "  Delivery Ratio: " << std::setprecision(1)
                    << ((double)statusReportsDelivered / statusReportsSent * 100) << "%\n";
        }
        logFile << "  Avg Latency: " << std::setprecision(4) << avgLatency << " s\n";

        logFile << "\n=== PACKETS ===\n";
        logFile << "  UDP packets sent: " << sentUdpPacketCount << "\n";
        logFile << "  WCA control packets sent: " << sentWcaPacketCount << "\n";
        logFile << "  Packets received: " << receivedPacketCount << "\n";
        logFile << "  Packets dropped: " << droppedPacketCount << "\n";
        logFile << "  Routing overhead: " << routingOverheadCount << "\n";

        logFile << "\n=== MODE TRANSITIONS ===\n";
        logFile << "  Total transitions: " << modeTransitions.size() << "\n";

        logFile << "=========================================\n";
        logFile.close();
    }

    if (csvFile.is_open()) {
        csvFile << "# FINAL," << nodeId << "," << energyConsumed << ","
                << lastLoggedEnergy << "," << (isCurrentlyCH ? 1 : 0) << ","
                << totalCHDuration << "," << chSelectionCount << ","
                << chReselectionCount << "," << sentUdpPacketCount << ","
                << sentWcaPacketCount << "," << receivedPacketCount << ","
                << droppedPacketCount << "," << routingOverheadCount << ","
                << static_cast<int>(currentMode) << "," << totalDisconnectedTime << ","
                << disconnectionCount << "," << totalGatewayTime << ","
                << gatewayElectionCount << "," << gatewayHandoverCount << ","
                << statusReportsSent << "," << statusReportsDelivered << ","
                << statusReportsForwarded << "," << hopsToServer << ","
                << connectivityRatio << "\n";
        csvFile.close();
    }
}

} // namespace hwca