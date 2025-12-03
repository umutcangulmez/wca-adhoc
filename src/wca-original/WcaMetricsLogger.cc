#include "WcaMetricsLogger.h"
#include <iomanip>
#include <sstream>
#include <ctime>
#include <sys/stat.h>

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
      routingOverheadCount(0)
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
        logFile << "WCA Simulation Metrics Log\n";
    }

    // Open csv file
    csvFile.open(csvFilePath, std::ios::out | std::ios::trunc);
    if (csvFile.is_open()) {
        csvFile << "time,node_id,energy_consumed,energy_remaining,is_ch,ch_duration_cumulative,"
                << "ch_selections_cumulative,ch_reselections_cumulative,"
                << "udp_packets_sent,wca_packets_sent,packets_received,packets_dropped,"
                << "routing_overhead\n";
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

    double idlePower = 0.5;           // W - radio idle/listening
    double txPower = 1.5;             // W - transmitting
    double rxPower = 1.0;             // W - receiving
    double chOverheadPower = 2;     // W - CH processing overhead
    double packetDuration = 0.002;    // 2ms per packet

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

    double energyConsumed = idleEnergy + txEnergy + rxEnergy + chEnergy;

    // Store for the energy over time tracking
    energyOverTime.push_back({time, energyConsumed});
    lastLoggedEnergy = initialEnergy - energyConsumed;  // Remaining energy

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
                << routingOverheadCount                 // routing_overhead
                << "\n";
        csvFile.flush();
    }

    // Write summary to log
    if (logFile.is_open()) {
        logFile << "\n--- Metrics at t=" << std::fixed << std::setprecision(2)
                << time.dbl() << "s ---\n";
        logFile << "  Energy consumed: " << std::setprecision(2) << energyConsumed << " J\n";
        logFile << "    - Idle (" << idleTime << "s): " << idleEnergy << " J\n";
        logFile << "    - TX (" << totalTxPackets << " pkts): " << txEnergy << " J\n";
        logFile << "    - RX (" << receivedPacketCount << " pkts): " << rxEnergy << " J\n";
        logFile << "    - CH overhead (" << currentCHDuration << "s): " << chEnergy << " J\n";
        logFile << "  Is CH: " << (isCurrentlyCH ? "YES" : "NO") << "\n";
        logFile << "  Total CH duration: " << std::setprecision(2) << currentCHDuration << " s\n";
        logFile << "  CH selections: " << chSelectionCount << "\n";
        logFile << "  UDP packets sent: " << sentUdpPacketCount << "\n";
        logFile << "  WCA packets sent: " << sentWcaPacketCount << "\n";
        logFile << "  Packets received: " << receivedPacketCount << "\n";
        logFile << "  Packets dropped: " << droppedPacketCount << "\n";
        logFile << "  Routing overhead: " << routingOverheadCount << "\n";
        logFile << "-----------------------------------\n\n";
        logFile.flush();
    }
}

void WCAMetricsLogger::finalizeAndClose()
{
    simtime_t endTime = simTime();

    // If still CH, log the final duration
    if (isCurrentlyCH) {
        double duration = (endTime - chStartTime).dbl();
        totalCHDuration += duration;
    }

    // Calculate final energy consumption
    double idlePower = 0.5;
    double txPower = 1.5;
    double rxPower = 1.0;
    double chOverheadPower = 0.2;
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

    double energyConsumed = idleEnergy + txEnergy + rxEnergy + chEnergy;
    lastLoggedEnergy = initialEnergy - energyConsumed;

    if (logFile.is_open()) {
        logFile << "FINAL SUMMARY - Node " << nodeId << "\n";
        logFile << "Simulation duration: " << std::fixed << std::setprecision(2)
                << endTime.dbl() << " s\n\n";

        logFile << "=== ENERGY ===\n";
        logFile << "  Total consumed: " << std::setprecision(2) << energyConsumed << " J\n";
        logFile << "    - Idle (" << idleTime << "s @ " << idlePower << "W): " << idleEnergy << " J\n";
        logFile << "    - TX (" << totalTxPackets << " pkts): " << txEnergy << " J\n";
        logFile << "    - RX (" << receivedPacketCount << " pkts): " << rxEnergy << " J\n";
        logFile << "    - CH overhead (" << totalCHDuration << "s): " << chEnergy << " J\n";
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
        logFile << "  CH reselections observed: " << chReselectionCount << "\n";

        logFile << "\n=== PACKETS ===\n";
        logFile << "  UDP packets sent: " << sentUdpPacketCount << "\n";
        logFile << "  WCA control packets sent: " << sentWcaPacketCount << "\n";
        logFile << "  Packets received: " << receivedPacketCount << "\n";
        logFile << "  Packets dropped: " << droppedPacketCount << "\n";
        logFile << "  Routing overhead (control msgs): " << routingOverheadCount << "\n";

        logFile.close();
    }

    if (csvFile.is_open()) {
        csvFile << "# FINAL," << nodeId << "," << energyConsumed << ","
                << lastLoggedEnergy << "," << (isCurrentlyCH ? 1 : 0) << ","
                << totalCHDuration << "," << chSelectionCount << ","
                << chReselectionCount << "," << sentUdpPacketCount << ","
                << sentWcaPacketCount << "," << receivedPacketCount << ","
                << droppedPacketCount << "," << routingOverheadCount << "\n";
        csvFile.close();
    }
}

} // namespace hwca
