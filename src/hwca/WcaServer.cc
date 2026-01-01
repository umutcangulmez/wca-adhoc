#include "WcaServer.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/common/InterfaceTag_m.h"


namespace hwca {

using namespace inet;

Define_Module(HwcaServer);

HwcaServer::~HwcaServer()
{
    if (networkProtocol)
        networkProtocol->unregisterHook(this);

    cancelAndDelete(broadcastTimer);
    cancelAndDelete(timeoutCheckTimer);
}

void HwcaServer::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // Initialize metrics
        totalStatusReportsReceived = 0;
        totalForwardedReportsReceived = 0;
        totalBroadcastsSent = 0;

        initializeMetrics();
        broadcastInterval = par("broadcastInterval");
        robotTimeoutThreshold = par("robotTimeoutThreshold");
        expectedRobotCount = par("expectedRobotCount");

        broadcastSequenceNumber = 0;

        broadcastTimer = new cMessage("broadcastTimer");
        timeoutCheckTimer = new cMessage("timeoutCheckTimer");

        robotStatusReceivedSignal = registerSignal("robotStatusReceived");
        robotDisconnectedSignal = registerSignal("robotDisconnected");
        connectedRobotCountSignal = registerSignal("connectedRobotCount");

        EV_INFO << "Server: INITSTAGE_LOCAL complete" << endl;
    }
    else if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        routingTable = getModuleFromPar<IIpv4RoutingTable>(par("routingTableModule"), this);

        // Find wireless interface
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            NetworkInterface *ie = interfaceTable->getInterface(i);
            if (strstr(ie->getInterfaceName(), "wlan") != nullptr) {
                interface80211 = ie;
                break;
            }
        }

        if (!interface80211) {
            for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
                NetworkInterface *ie = interfaceTable->getInterface(i);
                if (!ie->isLoopback()) {
                    interface80211 = ie;
                    break;
                }
            }
        }

        if (!interface80211)
            throw cRuntimeError("No suitable interface found for server");

        // Register netfilter hook
        networkProtocol = getModuleFromPar<INetfilter>(par("networkProtocolModule"), this);
        networkProtocol->registerHook(0, this);

        EV_INFO << "Server: INITSTAGE_ROUTING_PROTOCOLS complete" << endl;
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        EV_INFO << "Server: INITSTAGE_APPLICATION_LAYER at simTime=" << simTime() << endl;

        // Get IP address at this later stage
        auto ipv4Data = interface80211->findProtocolData<Ipv4InterfaceData>();
        if (ipv4Data) {
            myAddress = ipv4Data->getIPAddress();
        }

        EV_INFO << "HWCA Server initialized at " << myAddress << endl;
        EV_INFO << "  Broadcast interval: " << broadcastInterval << "s" << endl;
        EV_INFO << "  Robot timeout: " << robotTimeoutThreshold << "s" << endl;
        EV_INFO << "  Expected robots: " << expectedRobotCount << endl;

      // Schedule timers - THIS IS CRITICAL
      EV_INFO << "Server: Scheduling timers on module " << getFullPath() << endl;
      EV_INFO << "Server: this=" << this << ", getId()=" << getId() << endl;
      scheduleAt(simTime() + broadcastInterval, broadcastTimer);
      scheduleAt(simTime() + robotTimeoutThreshold / 2, timeoutCheckTimer);
      EV_INFO << "Server: broadcastTimer scheduled=" << broadcastTimer->isScheduled()
              << " at " << broadcastTimer->getArrivalTime() << endl;
      EV_INFO << "Server: timeoutCheckTimer scheduled=" << timeoutCheckTimer->isScheduled()
              << " at " << timeoutCheckTimer->getArrivalTime() << endl;
    }
}

  void HwcaServer::handleMessage(cMessage *msg)
{
  EV_INFO << "Server: handleMessage() called at t=" << simTime()
          << ", msg=" << msg->getName()
          << ", isSelfMessage=" << msg->isSelfMessage() << endl;

  if (msg->isSelfMessage()) {
    if (msg == broadcastTimer) {
      EV_INFO << "Server: broadcastTimer fired at t=" << simTime() << endl;
      sendBroadcast();
      logFleetStatus();
      logServerMetrics(simTime());  // Add this line
      scheduleAt(simTime() + broadcastInterval, broadcastTimer);
    }
    else if (msg == timeoutCheckTimer) {
      EV_INFO << "Server: timeoutCheckTimer fired at t=" << simTime() << endl;
      checkRobotTimeouts();
      emit(connectedRobotCountSignal, (long)connectedRobots.size());
      scheduleAt(simTime() + robotTimeoutThreshold / 2, timeoutCheckTimer);
    }
    else {
      EV_WARN << "Server: Unknown self-message: " << msg->getName() << endl;
    }
  }
  else {
    EV_WARN << "Server received unexpected external message: " << msg->getName() << endl;
    delete msg;
  }
}

INetfilter::IHook::Result HwcaServer::datagramPreRoutingHook(Packet *packet)
{
    try {
        const auto& networkHeader = packet->peekAtFront<Ipv4Header>();

        if (networkHeader->getProtocol() == &Protocol::manet) {
            auto wcaPacket = packet->peekDataAt<WcaPacket>(networkHeader->getChunkLength());
            if (wcaPacket) {
                processWcaPacket(packet, wcaPacket);
            }
            return DROP;
        }
    }
    catch (const std::exception& e) {
        EV_ERROR << "Server: Exception in datagramPreRoutingHook: " << e.what() << endl;
    }

    return ACCEPT;
}

void HwcaServer::processWcaPacket(Packet *packet, const Ptr<const WcaPacket>& wcaPacket)
{
    switch (wcaPacket->getPacketType()) {
        case WcaPacketType::STATUS_REPORT:
            processStatusReport(wcaPacket);
            break;
        case WcaPacketType::DATA_FORWARD:
            // Handle forwarded data
            {
              // Forwarded data from a gateway
              Ipv4Address originalSource = wcaPacket->getOriginalSource();
              EV_INFO << "Server received forwarded data from " << originalSource << endl;
              totalForwardedReportsReceived++;

              // Update robot state based on the forwarded packet
              RobotState& state = robotStates[originalSource];
              state.address = originalSource;
              state.lastReportTime = simTime();
              state.isConnected = true;

              // Add to connected set
              if (disconnectedRobots.find(originalSource) != disconnectedRobots.end()) {
                disconnectedRobots.erase(originalSource);
                EV_INFO << "Robot " << originalSource << " reconnected via gateway!" << endl;
              }
              connectedRobots.insert(originalSource);

              emit(robotStatusReceivedSignal, 1L);
            }
            break;
        default:
            EV_DEBUG << "Server ignoring packet type " << wcaPacket->getPacketType() << endl;
            break;
    }
}

void HwcaServer::processStatusReport(const Ptr<const WcaPacket>& wcaPacket)
{
    Ipv4Address robotAddr = wcaPacket->getSourceAddress();
    totalStatusReportsReceived++;

    emit(robotStatusReceivedSignal, 1L);

    updateRobotState(wcaPacket);

    EV_INFO << "Server received status from " << robotAddr
            << " [mode=" << networkModeToString(wcaPacket->getNetworkMode())
            << ", energy=" << (wcaPacket->getEnergyLevel() * 100) << "%"
            << ", seq=" << wcaPacket->getSequenceNumber() << "]" << endl;
}

void HwcaServer::updateRobotState(const Ptr<const WcaPacket>& wcaPacket)
{
    Ipv4Address robotAddr = wcaPacket->getSourceAddress();

    RobotState& state = robotStates[robotAddr];
    state.address = robotAddr;
    state.networkMode = wcaPacket->getNetworkMode();
    state.isClusterHead = wcaPacket->isClusterHead();
    state.clusterHead = wcaPacket->getClusterHeadAddress();
    state.gateway = wcaPacket->getGatewayAddress();
    state.energyLevel = wcaPacket->getEnergyLevel();
    state.taskInfo = wcaPacket->getTaskInfo();
    state.lastSequenceNumber = wcaPacket->getSequenceNumber();
    state.lastReportTime = simTime();
    state.isConnected = true;

    // Update connected set
    if (disconnectedRobots.find(robotAddr) != disconnectedRobots.end()) {
        disconnectedRobots.erase(robotAddr);
        EV_INFO << "Robot " << robotAddr << " reconnected!" << endl;
    }
    connectedRobots.insert(robotAddr);
}

void HwcaServer::checkRobotTimeouts()
{
    simtime_t now = simTime();

    for (auto& pair : robotStates) {
        RobotState& state = pair.second;

        if (state.isConnected && (now - state.lastReportTime) > robotTimeoutThreshold) {
            state.isConnected = false;
            connectedRobots.erase(pair.first);
            disconnectedRobots.insert(pair.first);

            emit(robotDisconnectedSignal, 1L);

            EV_WARN << "Robot " << pair.first << " TIMEOUT - no report for "
                    << (now - state.lastReportTime) << "s" << endl;
        }
    }
}

void HwcaServer::sendBroadcast(const char* command)
{
    totalBroadcastsSent++;

    Packet *packet = new Packet("HWCA-SERVER-BROADCAST");
    const auto& broadcast = makeShared<WcaPacket>();

    broadcast->setPacketType(WcaPacketType::SERVER_BROADCAST);
    broadcast->setSourceAddress(myAddress);
    broadcast->setDestAddress(Ipv4Address::ALLONES_ADDRESS);
    broadcast->setSequenceNumber(broadcastSequenceNumber++);
    broadcast->setServerCommand(command);
    broadcast->setTimestamp(simTime());
    broadcast->setChunkLength(B(64));

    packet->insertAtBack(broadcast);

    EV_INFO << "Server sending broadcast #" << (broadcastSequenceNumber - 1)
            << " command=\"" << command << "\"" << endl;

    sendPacket(packet, Ipv4Address::ALLONES_ADDRESS);
}

void HwcaServer::sendPacket(Packet *packet, const Ipv4Address& destAddr)
{
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::manet);
    packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

    auto addrReq = packet->addTagIfAbsent<L3AddressReq>();
    addrReq->setSrcAddress(L3Address(myAddress));
    addrReq->setDestAddress(L3Address(destAddr));

    packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(interface80211->getInterfaceId());

    send(packet, "ipOut");
}

void HwcaServer::logFleetStatus()
{
    EV_INFO << "========== FLEET STATUS ==========" << endl;
    EV_INFO << "Connected: " << connectedRobots.size() << "/" << expectedRobotCount << endl;
    EV_INFO << "Disconnected: " << disconnectedRobots.size() << endl;

    int gateways = 0;
    int directAP = 0;
    int clusterMembers = 0;
    int disconnected = 0;

    for (const auto& pair : robotStates) {
        const RobotState& state = pair.second;
        if (!state.isConnected) {
            disconnected++;
            continue;
        }

        switch (state.networkMode) {
            case 0: directAP++; break;      // DIRECT_AP
            case 1: gateways++; break;      // GATEWAY
            case 2: clusterMembers++; break; // CLUSTER_MEMBER
            case 3: disconnected++; break;   // DISCONNECTED
        }
    }

    EV_INFO << "  DIRECT_AP: " << directAP << endl;
    EV_INFO << "  GATEWAY: " << gateways << endl;
    EV_INFO << "  CLUSTER_MEMBER: " << clusterMembers << endl;
    EV_INFO << "  DISCONNECTED: " << disconnected << endl;
    EV_INFO << "==================================" << endl;
}

const char* HwcaServer::networkModeToString(int mode)
{
    switch (mode) {
        case 0: return "DIRECT_AP";
        case 1: return "GATEWAY";
        case 2: return "CLUSTER_MEMBER";
        case 3: return "DISCONNECTED";
        default: return "UNKNOWN";
    }
}

void HwcaServer::finish()
{
    finalizeServerMetrics();

    EV_INFO << "========== SERVER FINAL REPORT ==========" << endl;
    EV_INFO << "Total robots seen: " << robotStates.size() << endl;
    EV_INFO << "Final connected: " << connectedRobots.size() << endl;
    EV_INFO << "Final disconnected: " << disconnectedRobots.size() << endl;

    for (const auto& pair : robotStates) {
        const RobotState& state = pair.second;
        EV_INFO << "  Robot " << pair.first
                << ": mode=" << networkModeToString(state.networkMode)
                << ", energy=" << (state.energyLevel * 100) << "%"
                << ", connected=" << state.isConnected
                << ", lastReport=" << state.lastReportTime << endl;
    }
    EV_INFO << "==========================================" << endl;
}
  void HwcaServer::initializeMetrics()
{
  // Create results directory
  mkdir("results", 0755);

  // Open server CSV file
  serverCsvFile.open("results/hwca_server_metrics.csv", std::ios::out | std::ios::trunc);
  if (serverCsvFile.is_open()) {
    serverCsvFile << "time,connected_robots,disconnected_robots,"
                  << "direct_ap_count,gateway_count,cluster_member_count,disconnected_mode_count,"
                  << "status_reports_received,forwarded_reports_received,broadcasts_sent,"
                  << "connectivity_ratio\n";
  }

  // Open server log file
  serverLogFile.open("results/hwca_server_log.txt", std::ios::out | std::ios::trunc);
  if (serverLogFile.is_open()) {
    serverLogFile << "HWCA Server Metrics Log\n";
    serverLogFile << "========================\n\n";
  }
}
  void HwcaServer::logServerMetrics(simtime_t time)
{
    // Count modes
    int directAPCount = 0;
    int gatewayCount = 0;
    int clusterMemberCount = 0;
    int disconnectedModeCount = 0;

    for (const auto& pair : robotStates) {
        const RobotState& state = pair.second;
        if (!state.isConnected) continue;

        switch (state.networkMode) {
            case 0: directAPCount++; break;      // DIRECT_AP
            case 1: gatewayCount++; break;       // GATEWAY
            case 2: clusterMemberCount++; break; // CLUSTER_MEMBER
            case 3: disconnectedModeCount++; break; // DISCONNECTED
        }
    }

    // Calculate connectivity ratio
    double connectivityRatio = 0.0;
    if (expectedRobotCount > 0) {
        connectivityRatio = ((double)connectedRobots.size() / expectedRobotCount) * 100.0;
    }

    // Record history
    connectedCountHistory.push_back({time, (int)connectedRobots.size()});
    disconnectedCountHistory.push_back({time, (int)disconnectedRobots.size()});

    // Write to CSV
    if (serverCsvFile.is_open()) {
        serverCsvFile << std::fixed << std::setprecision(3)
                      << time.dbl() << ","
                      << connectedRobots.size() << ","
                      << disconnectedRobots.size() << ","
                      << directAPCount << ","
                      << gatewayCount << ","
                      << clusterMemberCount << ","
                      << disconnectedModeCount << ","
                      << totalStatusReportsReceived << ","
                      << totalForwardedReportsReceived << ","
                      << totalBroadcastsSent << ","
                      << std::setprecision(1) << connectivityRatio << "\n";
        serverCsvFile.flush();
    }

    // Write to log
    if (serverLogFile.is_open()) {
        serverLogFile << "[" << std::fixed << std::setprecision(2) << time.dbl() << "s] "
                      << "Connected: " << connectedRobots.size() << "/" << expectedRobotCount
                      << ", DIRECT_AP: " << directAPCount
                      << ", GATEWAY: " << gatewayCount
                      << ", CLUSTER_MEMBER: " << clusterMemberCount
                      << ", Status Reports: " << totalStatusReportsReceived << "\n";
    }
}

  void HwcaServer::finalizeServerMetrics()
{
    simtime_t endTime = simTime();

    // Calculate average connectivity
    double avgConnected = 0.0;
    if (!connectedCountHistory.empty()) {
        double sum = 0.0;
        for (const auto& pair : connectedCountHistory) {
            sum += pair.second;
        }
        avgConnected = sum / connectedCountHistory.size();
    }

    // Calculate time with full connectivity
    int fullConnectivityCount = 0;
    for (const auto& pair : connectedCountHistory) {
        if (pair.second >= expectedRobotCount) {
            fullConnectivityCount++;
        }
    }
    double fullConnectivityRatio = 0.0;
    if (!connectedCountHistory.empty()) {
        fullConnectivityRatio = ((double)fullConnectivityCount / connectedCountHistory.size()) * 100.0;
    }

    if (serverLogFile.is_open()) {
        serverLogFile << "\n=========================================\n";
        serverLogFile << "HWCA SERVER FINAL SUMMARY\n";
        serverLogFile << "=========================================\n";
        serverLogFile << "Simulation Duration: " << std::fixed << std::setprecision(2)
                      << endTime.dbl() << " s\n\n";

        serverLogFile << "=== CONNECTIVITY ===\n";
        serverLogFile << "  Expected Robots: " << expectedRobotCount << "\n";
        serverLogFile << "  Total Robots Seen: " << robotStates.size() << "\n";
        serverLogFile << "  Final Connected: " << connectedRobots.size() << "\n";
        serverLogFile << "  Final Disconnected: " << disconnectedRobots.size() << "\n";
        serverLogFile << "  Avg Connected Robots: " << std::setprecision(1) << avgConnected << "\n";
        serverLogFile << "  Full Connectivity Ratio: " << fullConnectivityRatio << "%\n";

        serverLogFile << "\n=== MESSAGE STATISTICS ===\n";
        serverLogFile << "  Total Status Reports Received: " << totalStatusReportsReceived << "\n";
        serverLogFile << "  Forwarded Reports Received: " << totalForwardedReportsReceived << "\n";
        serverLogFile << "  Broadcasts Sent: " << totalBroadcastsSent << "\n";

        serverLogFile << "\n=== FINAL ROBOT STATES ===\n";
        for (const auto& pair : robotStates) {
            const RobotState& state = pair.second;
            serverLogFile << "  " << pair.first << ": "
                          << "mode=" << networkModeToString(state.networkMode)
                          << ", energy=" << std::setprecision(0) << (state.energyLevel * 100) << "%"
                          << ", connected=" << (state.isConnected ? "YES" : "NO")
                          << ", lastReport=" << std::setprecision(2) << state.lastReportTime.dbl() << "s\n";
        }

        serverLogFile << "=========================================\n";
        serverLogFile.close();
    }

    if (serverCsvFile.is_open()) {
        serverCsvFile << "# FINAL SUMMARY\n";
        serverCsvFile << "# simulation_time," << endTime.dbl() << "\n";
        serverCsvFile << "# total_robots_seen," << robotStates.size() << "\n";
        serverCsvFile << "# avg_connected," << avgConnected << "\n";
        serverCsvFile << "# full_connectivity_ratio," << fullConnectivityRatio << "\n";
        serverCsvFile << "# total_status_reports," << totalStatusReportsReceived << "\n";
        serverCsvFile << "# forwarded_reports," << totalForwardedReportsReceived << "\n";
        serverCsvFile << "# broadcasts_sent," << totalBroadcastsSent << "\n";
        serverCsvFile.close();
    }
}
} // namespace hwca
