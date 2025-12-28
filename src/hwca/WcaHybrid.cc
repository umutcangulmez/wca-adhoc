#include "Wca.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/NextHopAddressTag_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/common/Ptr.h"
#include <omnetpp.h>
#include <sstream>
#include <iomanip>

namespace hwca {

using namespace inet;

Define_Module(Wca);

Wca::~Wca()
{
    // Unregister from netfilter before cleanup
    if (networkProtocol)
        networkProtocol->unregisterHook(this);

    cancelAndDelete(helloTimer);
    cancelAndDelete(clusterTimer);
    cancelAndDelete(metricTimer);
	cancelAndDelete(statusReportTimer);

    // Clean up visualization figures
    if (clusterMarker && canvas) {
        canvas->removeFigure(clusterMarker);
        delete clusterMarker;
    }
    for (auto& pair : connectionLines) {
        if (canvas) canvas->removeFigure(pair.second);
        delete pair.second;
    }
    if (weightText && canvas) {
        canvas->removeFigure(weightText);
        delete weightText;
    }
    if (statusText && canvas) {
        canvas->removeFigure(statusText);
        delete statusText;
    }
    for (auto* circle : apRangeCircles) {
        if (canvas) canvas->removeFigure(circle);
        delete circle;
    }

}

void Wca::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // Initialize parameters
        helloInterval = par("helloInterval");
        clusterTimeout = par("clusterTimeout");
        maxTransmissionPower = par("maxTransmissionPower");
        degreeWeight = par("degreeWeight");
        distanceWeight = par("distanceWeight");
        mobilityWeight = par("mobilityWeight");
        clusterHeadTimeWeight = par("clusterHeadTimeWeight");
        radioRange = par("radioRange");
        idealDegree = par("idealDegree");

        // HWCA Infrastructure parameters
        apDistanceWeight = par("apDistanceWeight");
        apSignalThreshold = par("apSignalThreshold");

        // HWCA State initialization
        networkMode = NetworkMode::DISCONNECTED;
        distanceToNearestAP = DBL_MAX;
        hasAPConnectivity = false;
        myGateway = Ipv4Address::UNSPECIFIED_ADDRESS;

        // Initialize state
        isClusterHead = false;
        myNodeId = -1;
        lastMobilityUpdate = simTime();

        // Initialize cumulative CH time tracking
        cumulativeCHTime = 0;
        lastCHStartTime = 0;

        // Initialize timers
        helloTimer = new cMessage("helloTimer");
        clusterTimer = new cMessage("clusterTimer");
        metricTimer = new cMessage("metricTimer");
        statusReportTimer = new cMessage("statusReportTimer");

        statusReportInterval = par("statusReportInterval");
        statusSequenceNumber = 0;

        packetIdCounter = 0;

        // Initialize signal
        clusterHeadChangedSignal = registerSignal("clusterHeadChanged");
        weightSignal = registerSignal("nodeWeight");
        neighborCountSignal = registerSignal("neighborCount");

        // Get canvas for visualization (from the network, not the host)
        cModule *network = getContainingNode(this)->getParentModule();
        canvas = network->getCanvas();

        // Initialize visualization elements
        clusterMarker = nullptr;
        weightText = nullptr;
        statusText = nullptr;
    }
    else if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        // Get module references
        interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        routingTable = getModuleFromPar<IIpv4RoutingTable>(par("routingTableModule"), this);

        // Find 802.11 interface
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            NetworkInterface *ie = interfaceTable->getInterface(i);
            if (strstr(ie->getInterfaceName(), "wlan") != nullptr) {
                interface80211 = ie;
                break;
            }
        }

        if (!interface80211)
            throw cRuntimeError("No wireless interface found");

        // Get my address
        myAddress = interface80211->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
        myNodeId = getContainingNode(this)->getIndex();

        // Get mobility module
        mobility = check_and_cast<IMobility *>(getParentModule()->getSubmodule("mobility"));
        previousPosition = mobility->getCurrentPosition();

        // Load AP positions from parameters
        const char *apPosStr = par("apPositions").stringValue();
        parseAPPositions(apPosStr);

        // Check initial AP connectivity
        hasAPConnectivity = checkAPConnectivity();
        distanceToNearestAP = getDistanceToNearestAP();
        updateNetworkMode();

        EV_INFO << "Node " << myNodeId << " initial AP connectivity: "
                << (hasAPConnectivity ? "YES" : "NO")
                << ", distance to nearest AP: " << distanceToNearestAP << "m"
                << ", mode: " << networkModeToString(networkMode) << endl;


        // Try to get energy storage
        cModule *host = getContainingNode(this);
        energyStorage = dynamic_cast<power::IEpEnergyStorage *>(
            host->getSubmodule("energyStorage"));

        // Register netfilter hook
        networkProtocol = getModuleFromPar<INetfilter>(par("networkProtocolModule"), this);
        networkProtocol->registerHook(0, this);

        // Initialize metric logger
        metricsLogger = new WCAMetricsLogger();
        std::string nodeIdStr = std::to_string(myNodeId);
        std::string logFile = "results/wca_performance_node" + nodeIdStr + ".log";
        std::string csvFile = "results/wca_metrics_node" + nodeIdStr + ".csv";
        metricsLogger->initialize(logFile.c_str(), csvFile.c_str());
        metricsLogger->setNodeId(myNodeId);

        // Set initial energy if available
        if (energyStorage) {
            double initialEnergy = energyStorage->getNominalEnergyCapacity().get();
            metricsLogger->setInitialEnergy(initialEnergy);
        }

        // Calculate initial weight
        myWeight = calculateWeight();
        EV_INFO << "Initial weight of node " << myAddress << " = " << myWeight << endl;

		// Get server address from parameter
        const char *serverAddrStr = par("serverAddress").stringValue();
        if (strlen(serverAddrStr) > 0) {
            serverAddress = Ipv4Address(serverAddrStr);
        } else {
            // todo default value for now
            serverAddress = Ipv4Address("10.0.0.1");
        }

        // Schedule first status report with random offset

        // Schedule first hello with random offset to avoid collisions
        scheduleAt(simTime() + uniform(0, 0.1), helloTimer);
        scheduleAt(simTime() + clusterTimeout, clusterTimer);
        scheduleAt(simTime() + 5.0, metricTimer);  // Start logging at 5s
        scheduleAt(simTime() + uniform(1.0, 2.0), statusReportTimer);

        // Beware that at startup, every node initially becomes a standalone clusterhead
        isClusterHead = true;
        myClusterHead = myAddress;
        lastCHStartTime = simTime();
        metricsLogger->logBecomeCH(simTime());
        EV_INFO << "Node " << myNodeId << " starting as initial CH" << endl;
        visualizeAPCoverage();

    }
}




void Wca::updateVisualization()
{
    Enter_Method_Silent();

    if (!canvas || !mobility) return;

    cModule *host = getContainingNode(this);
    Coord pos = mobility->getCurrentPosition();

    // Update or create cluster head marker
    if (isClusterHead) {
        if (!clusterMarker) {
            clusterMarker = new cOvalFigure("chMarker");
            clusterMarker->setFilled(false);
            clusterMarker->setLineWidth(3);
            canvas->addFigure(clusterMarker);
        }

        double markerRadius = 25;
        clusterMarker->setBounds(cFigure::Rectangle(
            pos.x - markerRadius, pos.y - markerRadius,
            markerRadius * 2, markerRadius * 2));
        clusterMarker->setLineColor(cFigure::Color("red"));
        clusterMarker->setVisible(true);

        host->getDisplayString().setTagArg("i", 1, "red");
    } else {
        if (clusterMarker) {
            clusterMarker->setVisible(false);
        }
        if (!myClusterHead.isUnspecified()) {
            host->getDisplayString().setTagArg("i", 1, "green");
        } else {
            host->getDisplayString().setTagArg("i", 1, "");
        }
    }

    // Update weight display text
    if (!weightText) {
        weightText = new cTextFigure("weightText");
        weightText->setFont(cFigure::Font("Arial", 10));
        weightText->setColor(cFigure::Color("blue"));
        canvas->addFigure(weightText);
    }

    std::ostringstream oss;
    oss << "W:" << std::fixed << std::setprecision(2) << myWeight;
    weightText->setText(oss.str().c_str());
    weightText->setPosition(cFigure::Point(pos.x + 15, pos.y - 20));

    // Update status text (Network Mode + CH/Member)
    if (!statusText) {
        statusText = new cTextFigure("statusText");
        canvas->addFigure(statusText);
    }

    std::ostringstream statusOss;

    // Show network mode
    switch (networkMode) {
        case NetworkMode::DIRECT_AP:
            statusOss << "[AP]";
            statusText->setColor(cFigure::Color("blue"));
            host->getDisplayString().setTagArg("i", 1, "blue");
            break;
        case NetworkMode::GATEWAY: {
            int outsideMembers = 0;
            for (const auto& memberAddr : clusterMembers) {
                auto it = neighbors.find(memberAddr);
                if (it != neighbors.end() && !it->second.hasAPConnectivity) {
                    outsideMembers++;
                }
            }
            statusOss << "[GW:" << outsideMembers << "]";
            statusText->setColor(cFigure::Color("purple"));
            host->getDisplayString().setTagArg("i", 1, "purple");
            break;
        }
        case NetworkMode::CLUSTER_MEMBER:
            statusOss << "[M->N" << getNodeIdFromAddress(myGateway) << "]";
            statusText->setColor(cFigure::Color("green"));
            host->getDisplayString().setTagArg("i", 1, "green");
            break;
        case NetworkMode::DISCONNECTED:
            statusOss << "[DISC]";
            statusText->setColor(cFigure::Color("red"));
            host->getDisplayString().setTagArg("i", 1, "red");
            break;
    }

    // Add CH info if cluster head
    if (isClusterHead) {
        statusOss << " CH";
    }

    statusText->setText(statusOss.str().c_str());
    statusText->setPosition(cFigure::Point(pos.x + 15, pos.y + 5));

    updateConnectionLines();
}

void Wca::updateConnectionLines()
{
    if (!canvas || !mobility) return;

    for (auto& pair : connectionLines) {
        canvas->removeFigure(pair.second);
        delete pair.second;
    }
    connectionLines.clear();

    if (isClusterHead) {
        for (const auto& memberAddr : clusterMembers) {
            drawConnectionLine(memberAddr, "blue", 1);
        }
    } else if (!myClusterHead.isUnspecified()) {
        drawConnectionLine(myClusterHead, "green", 2);
    }
}

void Wca::drawConnectionLine(const Ipv4Address& targetAddr, const char* color, int width)
{
    if (!canvas || !mobility) return;

    int targetNodeId = getNodeIdFromAddress(targetAddr);
    if (targetNodeId < 0) return;

    cModule *network = getContainingNode(this)->getParentModule();
    cModule *targetHost = network->getSubmodule("host", targetNodeId);
    if (!targetHost) return;

    IMobility *targetMobility = dynamic_cast<IMobility*>(targetHost->getSubmodule("mobility"));
    if (!targetMobility) return;

    Coord myPos = mobility->getCurrentPosition();
    Coord targetPos = targetMobility->getCurrentPosition();

    std::string lineName = "line_" + std::to_string(myNodeId) + "_" + std::to_string(targetNodeId);
    cLineFigure *line = new cLineFigure(lineName.c_str());
    line->setStart(cFigure::Point(myPos.x, myPos.y));
    line->setEnd(cFigure::Point(targetPos.x, targetPos.y));
    line->setLineColor(cFigure::Color(color));
    line->setLineWidth(width);
    line->setLineStyle(cFigure::LINE_DASHED);

    canvas->addFigure(line);
    connectionLines[targetAddr] = line;
}

int Wca::getNodeIdFromAddress(const Ipv4Address& addr)
{
    uint32_t ipInt = addr.getInt();
    int nodeId = (ipInt & 0xFF) - 1;
    return nodeId;
}


void Wca::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (msg == helloTimer) {
            sendHelloPacket();
            scheduleAt(simTime() + helloInterval, helloTimer);
        }
        else if (msg == clusterTimer) {
            performClusterElection();
            removeStaleNeighbors();
            checkGatewayHandover();
            updateVisualization();
            scheduleAt(simTime() + clusterTimeout, clusterTimer);
        }
        else if (msg == metricTimer) {
            if (energyStorage) {
                double currentEnergy = energyStorage->getResidualEnergyCapacity().get();
                metricsLogger->logEnergy(currentEnergy, simTime());
            }

            metricsLogger->calculateAndLogMetrics(simTime());
            emit(weightSignal, myWeight);
            emit(neighborCountSignal, (long)neighbors.size());
            scheduleAt(simTime() + 5.0, msg);  // Log every 5 seconds for better resolution
        }
        else if (msg == statusReportTimer) {
            sendStatusReport();
            scheduleAt(simTime() + statusReportInterval, statusReportTimer);
        }
    }
    else {
        EV_WARN << "Unexpected packet received in handleMessage" << endl;
        delete msg;
    }
}

void Wca::sendHelloPacket()
{
    Packet *packet = new Packet("WCA-HELLO");
    const auto& hello = makeShared<WcaPacket>();

    myWeight = calculateWeight();
    hello->setPacketType(WcaPacketType::HELLO);
    hello->setSourceAddress(myAddress);
    hello->setDestAddress(Ipv4Address::ALLONES_ADDRESS);
    hello->setWeight(myWeight);
    hello->setNodeDegree(getNodeDegree());
    hello->setTransmissionPower(maxTransmissionPower);
    hello->setMobility(calculateMobility());
    hello->setBatteryPower(1.0);  // Not used in correct WCA
    hello->setIsClusterHead(isClusterHead);
    hello->setClusterHeadAddress(isClusterHead ? myAddress : myClusterHead);
    hello->setHasAPConnectivity(hasAPConnectivity);
    hello->setDistanceToAP(distanceToNearestAP);

    if (hasAPConnectivity && isClusterHead) {
        hello->setGatewayScore(calculateGatewayScore());
    } else {
        hello->setGatewayScore(-1);
    }

    hello->setTimestamp(simTime());
    hello->setChunkLength(B(64));

    packet->insertAtBack(hello);
    packet->addPar("hopCount") = 0;

    EV_DEBUG << "Node " << myNodeId << " sending HELLO, weight=" << myWeight
             << ", isCH=" << isClusterHead << ", neighbors=" << neighbors.size() << endl;

    sendPacket(packet, Ipv4Address::ALLONES_ADDRESS);
}

void Wca::processHelloPacket(const Ptr<const WcaPacket>& wcaPacket)
{
    auto srcAddr = wcaPacket->getSourceAddress();

    if (srcAddr == myAddress)
        return;

    updateNeighborInfo(wcaPacket, srcAddr);

    // Update network mode based on new neighbor info
    updateNetworkMode();

    EV_DEBUG << "Node " << myNodeId << " received HELLO from " << srcAddr
             << ", weight=" << wcaPacket->getWeight()
             << ", isCH=" << wcaPacket->isClusterHead()
             << ", hasAP=" << wcaPacket->getHasAPConnectivity() << endl;
    checkGatewayHandover();
}

void Wca::performClusterElection()
{
    myWeight = calculateWeight();

    EV_INFO << "=== Node " << myNodeId << " cluster election ===" << endl;
    EV_INFO << "  My weight: " << myWeight << ", Neighbors: " << neighbors.size() << endl;

    // If no neighbors, node must be CH (beware: isolated node)
    if (neighbors.empty()) {
        if (!isClusterHead) {
            EV_INFO << "  -> No neighbors, becoming standalone CH" << endl;
            becomeClusterHead();
            emit(clusterHeadChangedSignal, true);
        }
        return;
    }

    // Find if there's an existing CH neighbor with lower weight than me
    Ipv4Address bestNeighborCH;
    double bestNeighborCHWeight = DBL_MAX;

    // Find the neighbor with lowest weight (whether CH or not)
    Ipv4Address lowestWeightNeighbor;
    double lowestNeighborWeight = DBL_MAX;

    for (const auto& pair : neighbors) {
        EV_DEBUG << "  Neighbor " << pair.first << ": weight=" << pair.second.weight
                 << ", isCH=" << pair.second.isClusterHead << endl;

        // Track best existing CH neighbor
        if (pair.second.isClusterHead && pair.second.weight < bestNeighborCHWeight) {
            bestNeighborCHWeight = pair.second.weight;
            bestNeighborCH = pair.first;
        }

        // Track lowest weight neighbor overall
        if (pair.second.weight < lowestNeighborWeight) {
            lowestNeighborWeight = pair.second.weight;
            lowestWeightNeighbor = pair.first;
        }
        else if (pair.second.weight == lowestNeighborWeight && pair.first < lowestWeightNeighbor) {
            lowestWeightNeighbor = pair.first;
        }
    }

    // Determine if I should be CH
    bool shouldBeClusterHead = true;


    if (lowestNeighborWeight < myWeight) {
        shouldBeClusterHead = false;
    }
    else if (lowestNeighborWeight == myWeight && lowestWeightNeighbor < myAddress) {
        shouldBeClusterHead = false;
    }

    bool wasClusterHead = isClusterHead;

    if (shouldBeClusterHead) {
        if (!isClusterHead) {
            EV_INFO << "  -> Becoming Cluster Head (lowest weight)" << endl;
            becomeClusterHead();
        } else {
            EV_INFO << "  -> Remain CH with " << clusterMembers.size() << " members" << endl;
        }
    }
    else {
        // I should NOT be CH - but only step down if there's an EXISTING CH to join
        // OR if the lower-weight neighbor is already a CH

        bool canStepDown = false;
        Ipv4Address chToJoin;

        // there's an existing CH neighbor
        if (!bestNeighborCH.isUnspecified()) {
            canStepDown = true;
            chToJoin = bestNeighborCH;
            EV_DEBUG << "  Can step down: existing CH " << bestNeighborCH << endl;
        }
        // The lowest weight neighbor is already a CH
        else if (!lowestWeightNeighbor.isUnspecified()) {
            auto it = neighbors.find(lowestWeightNeighbor);
            if (it != neighbors.end() && it->second.isClusterHead) {
                canStepDown = true;
                chToJoin = lowestWeightNeighbor;
                EV_DEBUG << "  Can step down: lowest weight neighbor " << lowestWeightNeighbor << " is CH" << endl;
            }
        }

        if (isClusterHead) {
            if (canStepDown) {
                // Safe to step down - there's a CH to join
                EV_INFO << "  -> Stepping down from CH, joining " << chToJoin << endl;
                stepDownFromClusterHead();
                joinCluster(chToJoin);
            } else {
                // NOT safe to step down - remain CH until a better CH emerges
                EV_INFO << "  -> Should step down but no CH available, remaining CH" << endl;
                // Stay as CH - don't leave network without a CH!
            }
        }
        else {
            // I'm not CH - find a cluster to join
            if (!bestNeighborCH.isUnspecified()) {
                if (myClusterHead != bestNeighborCH) {
                    joinCluster(bestNeighborCH);
                }
            } else {
                // No CH neighbor - use findAndJoinBestCluster which will make me CH if needed
                findAndJoinBestCluster();
            }
        }
    }

    if (wasClusterHead != isClusterHead) {
        emit(clusterHeadChangedSignal, isClusterHead);
    }

    if (hasAPConnectivity && isClusterHead) {
        triggerGatewayElection();
    }


    updateNetworkMode();
}

void Wca::becomeClusterHead()
{
    isClusterHead = true;
    myClusterHead = myAddress;
    clusterMembers.clear();

    // Track when this CH period started
    lastCHStartTime = simTime();

    EV_INFO << "Node " << myNodeId << " became cluster head (total CH time: "
            << cumulativeCHTime << "s)" << endl;

    metricsLogger->logBecomeCH(simTime());

    cModule *host = getContainingNode(this);
    host->bubble("CH!");

    Packet *packet = new Packet("WCA-CH-ANNOUNCE");
    const auto& announce = makeShared<WcaPacket>();

    announce->setPacketType(WcaPacketType::CLUSTER_HEAD_ANNOUNCEMENT);
    announce->setSourceAddress(myAddress);
    announce->setDestAddress(Ipv4Address::ALLONES_ADDRESS);
    announce->setClusterHeadAddress(myAddress);
    announce->setWeight(myWeight);
    announce->setIsClusterHead(true);
    announce->setChunkLength(B(32));

    packet->insertAtBack(announce);
    sendPacket(packet, Ipv4Address::ALLONES_ADDRESS);
}

void Wca::stepDownFromClusterHead()
{
    // Accumulate CH time before stepping down
    if (lastCHStartTime > 0) {
        cumulativeCHTime += (simTime() - lastCHStartTime);
        EV_INFO << "Node " << myNodeId << " stepping down, was CH for "
                << (simTime() - lastCHStartTime) << "s (total: " << cumulativeCHTime << "s)" << endl;
    }
    lastCHStartTime = 0;

    metricsLogger->logStopCH(simTime());
    metricsLogger->logCHReselection(simTime());

    isClusterHead = false;
    clusterMembers.clear();
    myClusterHead = Ipv4Address::UNSPECIFIED_ADDRESS;

    cModule *host = getContainingNode(this);
    host->getDisplayString().setTagArg("i", 1, "");
}

void Wca::findAndJoinBestCluster()
{
    Ipv4Address bestCH;
    double bestWeight = DBL_MAX;

    // Look for existing cluster heads among neighbors first
    for (const auto& pair : neighbors) {
        if (pair.second.isClusterHead && pair.second.weight < bestWeight) {
            bestWeight = pair.second.weight;
            bestCH = pair.first;
        }
    }

    // If found a CH neighbor, join it
    if (!bestCH.isUnspecified()) {
        joinCluster(bestCH);
        return;
    }

    // No CH neighbor found - check if I should become CH
    bool iHaveLowestWeight = true;
    bestWeight = DBL_MAX;

    for (const auto& pair : neighbors) {
        if (pair.second.weight < myWeight) {
            iHaveLowestWeight = false;
        }
        else if (pair.second.weight == myWeight && pair.first < myAddress) {
            iHaveLowestWeight = false;
        }

        // Track lowest weight neighbor
        if (pair.second.weight < bestWeight) {
            bestWeight = pair.second.weight;
            bestCH = pair.first;
        }
    }

    if (neighbors.empty()) {
        // Isolated node - become CH
        EV_INFO << "Node " << myNodeId << ": Isolated, becoming standalone CH" << endl;
        becomeClusterHead();
    }
    else if (iHaveLowestWeight) {
        // I have lowest weight - I should be CH
        EV_INFO << "Node " << myNodeId << ": Lowest weight among neighbors, becoming CH" << endl;
        becomeClusterHead();
    }
    else if (!bestCH.isUnspecified()) {
        // Join lowest weight neighbor
        joinCluster(bestCH);
    }
    else {
        // Fallback - become CH to ensure there's always one
        EV_INFO << "Node " << myNodeId << ": Fallback, becoming CH" << endl;
        becomeClusterHead();
    }
}

void Wca::joinCluster(const Ipv4Address& chAddress)
{
    myClusterHead = chAddress;

    EV_INFO << "Node " << myNodeId << " joining cluster headed by " << chAddress << endl;

    Packet *packet = new Packet("WCA-JOIN-REQ");
    const auto& joinReq = makeShared<WcaPacket>();

    joinReq->setPacketType(WcaPacketType::JOIN_REQUEST);
    joinReq->setSourceAddress(myAddress);
    joinReq->setDestAddress(chAddress);
    joinReq->setClusterHeadAddress(chAddress);
    joinReq->setChunkLength(B(32));

    packet->insertAtBack(joinReq);
    sendPacket(packet, chAddress);

    updateVisualization();
}

void Wca::processCHAnnouncement(const Ptr<const WcaPacket>& wcaPacket)
{
    auto chAddr = wcaPacket->getClusterHeadAddress();
    double chWeight = wcaPacket->getWeight();

    // Update neighbor info to mark them as CH
    auto it = neighbors.find(chAddr);
    if (it != neighbors.end()) {
        it->second.isClusterHead = true;
        it->second.clusterHeadAddress = chAddr;
        it->second.weight = chWeight;
    }

    if (isClusterHead) {
        // I'm a CH - Only step down if the new CH has lower weight AND is my neighbor
        if (it != neighbors.end() && chWeight < myWeight) {
            EV_INFO << "Node " << myNodeId << ": Received CH announcement from " << chAddr
                    << " with lower weight (" << chWeight << " < " << myWeight << "), stepping down" << endl;
            stepDownFromClusterHead();
            joinCluster(chAddr);
        }
        // Tie-breaker: lower IP wins
        else if (it != neighbors.end() && chWeight == myWeight && chAddr < myAddress) {
            EV_INFO << "Node " << myNodeId << ": Received CH announcement from " << chAddr
                    << " with same weight but lower IP, stepping down" << endl;
            stepDownFromClusterHead();
            joinCluster(chAddr);
        }
    }
    else {
        // I'm not a CH
        bool shouldJoin = myClusterHead.isUnspecified();

        if (!shouldJoin && myClusterHead != chAddr) {
            auto currentCHIt = neighbors.find(myClusterHead);
            // Join new CH if: current CH is gone OR new CH has lower weight
            if (currentCHIt == neighbors.end() || !currentCHIt->second.isClusterHead ||
                chWeight < currentCHIt->second.weight) {
                shouldJoin = true;
            }
        }

        if (shouldJoin) {
            joinCluster(chAddr);
        }
    }
}

void Wca::processJoinRequest(const Ptr<const WcaPacket>& wcaPacket)
{
    if (!isClusterHead) return;

    auto memberAddr = wcaPacket->getSourceAddress();

    clusterMembers.insert(memberAddr);

    EV_INFO << "Node " << memberAddr << " joined cluster (" << clusterMembers.size() << " members)" << endl;

    Packet *replyPacket = new Packet("WCA-JOIN-REPLY");
    const auto& joinReply = makeShared<WcaPacket>();

    joinReply->setPacketType(WcaPacketType::JOIN_REPLY);
    joinReply->setSourceAddress(myAddress);
    joinReply->setDestAddress(memberAddr);
    joinReply->setClusterHeadAddress(myAddress);
    joinReply->setChunkLength(B(32));

    replyPacket->insertAtBack(joinReply);
    sendPacket(replyPacket, memberAddr);

    // Check if node become a gateway
    updateNetworkMode();

    updateVisualization();
}

void Wca::processJoinReply(const Ptr<const WcaPacket>& wcaPacket)
{
    myClusterHead = wcaPacket->getClusterHeadAddress();

    EV_INFO << "Node " << myNodeId << ": Join confirmed by CH " << myClusterHead << endl;

    updateVisualization();
}

double Wca::calculateWeight()
{
    // HWCA formula (extended from WCA):
    // W = w1*Δv + w2*Dv + w3*Mv + w4*Pv + w5*Av

    int degree = getNodeDegree();
    double sumDistances = getSumOfDistances();
    double mob = calculateMobility();
    double chTime = getCumulativeCHTime();
    double apDist = getDistanceToNearestAP();

    double degreeDiff = std::abs(degree - idealDegree);

    // Normalize factors to [0, 1]
    double normDegreeDiff = std::min(degreeDiff / (double)idealDegree, 1.0);
    double normSumDistances = std::min(sumDistances / (radioRange * idealDegree), 1.0);
    double normMobility = std::min(mob / 20.0, 1.0);
    double normCHTime = std::min(chTime / 100.0, 1.0);

    // Normalize AP distance: 0 = at AP, 1 = at or beyond radio range
    double normAPDistance = std::min(apDist / radioRange, 1.0);

    // Lower weight = better CH candidate
    // Nodes closer to APs get lower weight (better gateway candidates)
    double weight = degreeWeight * normDegreeDiff +
                    distanceWeight * normSumDistances +
                    mobilityWeight * normMobility +
                    clusterHeadTimeWeight * normCHTime +
                    apDistanceWeight * normAPDistance;

    return weight;
}

double Wca::calculateMobility()
{
    Coord currentPos = mobility->getCurrentPosition();
    double distance = currentPos.distance(previousPosition);
    double timeElapsed = (simTime() - lastMobilityUpdate).dbl();

    double speed = (timeElapsed > 0) ? distance / timeElapsed : 0.0;

    previousPosition = currentPos;
    lastMobilityUpdate = simTime();

    return speed;
}

double Wca::getSumOfDistances()
{
    if (!mobility || neighbors.empty()) return 0.0;

    Coord myPos = mobility->getCurrentPosition();
    double totalDistance = 0.0;

    cModule *network = getContainingNode(this)->getParentModule();

    for (const auto& pair : neighbors) {
        int neighborId = getNodeIdFromAddress(pair.first);
        if (neighborId < 0) continue;

        cModule *neighborHost = network->getSubmodule("host", neighborId);
        if (!neighborHost) continue;

        IMobility *neighborMobility = dynamic_cast<IMobility*>(
            neighborHost->getSubmodule("mobility"));
        if (!neighborMobility) continue;

        Coord neighborPos = neighborMobility->getCurrentPosition();
        totalDistance += myPos.distance(neighborPos);
    }

    return totalDistance;
}

double Wca::getCumulativeCHTime()
{
    double totalTime = cumulativeCHTime.dbl();

    // Add current CH period if currently a CH
    if (isClusterHead && lastCHStartTime > 0) {
        totalTime += (simTime() - lastCHStartTime).dbl();
    }

    return totalTime;
}

int Wca::getNodeDegree()
{
    return neighbors.size();
}

void Wca::updateNeighborInfo(const Ptr<const WcaPacket>& wcaPacket, const Ipv4Address& senderAddr)
{
    NeighborInfo& info = neighbors[senderAddr];
    info.address = senderAddr;
    info.weight = wcaPacket->getWeight();
    info.nodeDegree = wcaPacket->getNodeDegree();
    info.transmissionPower = wcaPacket->getTransmissionPower();
    info.mobility = wcaPacket->getMobility();
    info.batteryPower = wcaPacket->getBatteryPower();
    info.isClusterHead = wcaPacket->isClusterHead();
    info.clusterHeadAddress = wcaPacket->getClusterHeadAddress();
    info.lastSeen = simTime();
    info.hasAPConnectivity = wcaPacket->getHasAPConnectivity();
    info.gatewayScore = wcaPacket->getGatewayScore();

}

void Wca::removeStaleNeighbors()
{
    auto it = neighbors.begin();
    while (it != neighbors.end()) {
        if (simTime() - it->second.lastSeen > clusterTimeout) {
            clusterMembers.erase(it->first);
            it = neighbors.erase(it);
        } else {
            ++it;
        }
    }
}


void Wca::sendPacket(Packet *packet, const Ipv4Address& destAddr)
{
    Enter_Method("sendPacket");

    if (packet->getOwner() != this)
        take(packet);

    // Assign packet ID for metrics
    int packetId = packetIdCounter++;

    metricsLogger->logPacketSent(packetId, myNodeId, destAddr.getInt(), simTime());

    if (!packet->hasPar("hopCount"))
        packet->addPar("hopCount") = 0;

    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::manet);
    packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

    // Wrap addresses as L3Address
    L3Address srcL3(myAddress);
    L3Address dstL3(destAddr);

    // Add IPv4 addresses
    Ptr<L3AddressReq> addrReq = packet->addTagIfAbsent<L3AddressReq>();
    addrReq->setSrcAddress(srcL3);
    addrReq->setDestAddress(dstL3);

    packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(interface80211->getInterfaceId());

    send(packet, "ipOut");
}

INetfilter::IHook::Result Wca::datagramPreRoutingHook(Packet *packet)
{
    try { // try catch added for an error in message size. todo check the issue
        const auto& networkHeader = packet->peekAtFront<Ipv4Header>();

        if (networkHeader->getProtocol() == &Protocol::manet) {
            EV_DEBUG << "WCA packet received via netfilter hook from "
                     << networkHeader->getSrcAddress() << endl;

            try {
                auto wcaPacket = packet->peekDataAt<WcaPacket>(networkHeader->getChunkLength());
                if (wcaPacket) {
                    processWcaPacket(packet, wcaPacket);
                }
            }
            catch (const std::exception& e) {
                EV_ERROR << "Failed to parse WcaPacket: " << e.what() << endl;
            }

            return DROP;
        }
        else if (networkHeader->getProtocol() == &Protocol::udp) {
            Ipv4Address destAddr = networkHeader->getDestAddress();

            if (destAddr == myAddress) {
                return ACCEPT;
            }

            if (!destAddr.isLimitedBroadcastAddress()) {
                forwardDataPacket(packet);
                return DROP;
            }

            return ACCEPT;
        }
    }
    catch (const std::exception& e) {
        EV_ERROR << "Exception in datagramPreRoutingHook: " << e.what() << endl;
    }

    return ACCEPT;
}

void Wca::processWcaPacket(Packet *packet, const Ptr<const WcaPacket>& wcaPacket)
{
    Enter_Method("processWcaPacket");

    switch (wcaPacket->getPacketType()) {
        case WcaPacketType::HELLO:
            processHelloPacket(wcaPacket);
            metricsLogger->logRoutingOverhead(1);
            break;
        case WcaPacketType::CLUSTER_HEAD_ANNOUNCEMENT:
            processCHAnnouncement(wcaPacket);
            metricsLogger->logRoutingOverhead(1);
            break;
        case WcaPacketType::JOIN_REQUEST:
            processJoinRequest(wcaPacket);
            metricsLogger->logRoutingOverhead(1);
            break;
        case WcaPacketType::JOIN_REPLY:
            processJoinReply(wcaPacket);
            metricsLogger->logRoutingOverhead(1);
            break;
		case WcaPacketType::GATEWAY_ANNOUNCE:
            processGatewayAnnouncement(wcaPacket);
            metricsLogger->logRoutingOverhead(1);
            break;
		case WcaPacketType::DATA_FORWARD:
            processDataForward(packet, wcaPacket);
            break;
        case WcaPacketType::STATUS_REPORT:
            processStatusReport(wcaPacket);
            break;
        case WcaPacketType::SERVER_BROADCAST:
            processServerBroadcast(wcaPacket);
            break;
		case WcaPacketType::GATEWAY_DISCOVERY_REQUEST:
            processGatewayDiscoveryRequest(wcaPacket);
            metricsLogger->logRoutingOverhead(1);
            break;
        case WcaPacketType::GATEWAY_DISCOVERY_REPLY:
            processGatewayDiscoveryReply(wcaPacket);
            metricsLogger->logRoutingOverhead(1);
            break;
        default:
            EV_WARN << "Unknown WCA packet type" << endl;
            break;
    }
}

void Wca::forwardDataPacket(Packet *packet)
{
    Enter_Method("forwardDataPacket");

    // Safety check todo there is an issue with size here
    if (packet->getDataLength() < B(20)) {
        EV_WARN << "Packet too small to contain IPv4 header, dropping" << endl;
        return;
    }

    auto ipv4Header = packet->peekAtFront<Ipv4Header>();
    Ipv4Address dest = ipv4Header->getDestAddress();
    Ipv4Address source = ipv4Header->getSrcAddress();
    Ipv4Address nextHop;

    int packetId = packetIdCounter++;

    // If a node is outside of a AP range, use gateway for external destinations
    if (networkMode == NetworkMode::CLUSTER_MEMBER && !myGateway.isUnspecified()) {
        // Condition for gateway need
        if (neighbors.find(dest) == neighbors.end()) {
            EV_INFO << "Node " << myNodeId << " using gateway " << myGateway
                    << " for forwarding to " << dest << endl;
            sendDataThroughGateway(packet->dup(), dest);
            return;
        }
    }

    // If destination is a direct neighbor, send directly
    if (neighbors.find(dest) != neighbors.end()) {
        nextHop = dest;
        EV_INFO << "Forwarding directly to neighbor " << dest << "\n";
    }

    // If current node is a cluster head
    else if (isClusterHead) {
        // Check if destination is a cluster member
        if (clusterMembers.find(dest) != clusterMembers.end()) {
            nextHop = dest;
            EV_INFO << "CH forwarding to member " << dest << "\n";
        }
        // Forward to neighboring cluster head
        else {
            // Find a neighboring CH that might have the destination
            for (const auto& neighbor : neighbors) {
                if (neighbor.second.isClusterHead) {
                    nextHop = neighbor.first;
                    EV_INFO << "CH forwarding to neighboring CH " << nextHop << "\n";
                    break;
                }
            }

            // If no CH neighbor found, try any neighbor
            if (nextHop.isUnspecified() && !neighbors.empty()) {
                nextHop = neighbors.begin()->first;
                EV_INFO << "CH forwarding to any neighbor " << nextHop << "\n";
            }
        }
    }
    // If this node is a cluster member
    else {
        // Forward to cluster head
        if (!myClusterHead.isUnspecified()) {
            nextHop = myClusterHead;
            EV_INFO << "Member forwarding to CH " << myClusterHead << "\n";
        }
        // If no CH, try direct neighbor
        else if (!neighbors.empty()) {
            nextHop = neighbors.begin()->first;
            EV_INFO << "Forwarding to neighbor (no CH) " << nextHop << "\n";
        }
    }

    // Drop packet if no route found
    if (nextHop.isUnspecified()) {
        EV_WARN << "No route to " << dest << ", dropping packet" << endl;
        metricsLogger->logPacketDropped(packetId, myNodeId, "No route", simTime());
        return;
    }

    Packet *fwdPacket = new Packet(packet->getName());

    auto payload = packet->peekDataAt(ipv4Header->getChunkLength(),
                                       packet->getDataLength() - ipv4Header->getChunkLength());
    fwdPacket->insertAtBack(payload);

    int hopCount = 0;
    if (packet->hasPar("hopCount")) {
        hopCount = packet->par("hopCount").longValue() + 1;
    }
    fwdPacket->addPar("hopCount") = hopCount;

    fwdPacket->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::udp);
    fwdPacket->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

    auto addrReq = fwdPacket->addTagIfAbsent<L3AddressReq>();
    addrReq->setSrcAddress(L3Address(source));
    addrReq->setDestAddress(L3Address(dest));

    fwdPacket->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(L3Address(nextHop));
    fwdPacket->addTagIfAbsent<InterfaceReq>()->setInterfaceId(interface80211->getInterfaceId());

    EV_DEBUG << "Forwarding packet to " << nextHop << " (dest=" << dest << ")" << endl;
    send(fwdPacket, "ipOut");
}

void Wca::finish()
{
    // Update final CH time if still a CH
    if (isClusterHead && lastCHStartTime > 0) {
        cumulativeCHTime += (simTime() - lastCHStartTime);
    }

    EV_INFO << "=== Node " << myNodeId << " Final Statistics ===" << endl
            << "  CH status: " << (isClusterHead ? "Cluster Head" : "Member") << endl
            << "  Cluster head: " << (isClusterHead ? myAddress : myClusterHead) << endl
            << "  Neighbors: " << neighbors.size() << endl
            << "  Cluster members: " << clusterMembers.size() << endl
            << "  Final weight: " << myWeight << endl
            << "  Total CH time: " << cumulativeCHTime << "s" << endl;

    if (metricsLogger) {
        metricsLogger->finalizeAndClose();
        delete metricsLogger;
        metricsLogger = nullptr;
    }
}
void Wca::parseAPPositions(const char* apPosStr)
{
    apPositions.clear();

    if (!apPosStr || strlen(apPosStr) == 0) {
        EV_WARN << "No AP positions configured" << endl;
        return;
    }

    // Parse format: "x1,y1;x2,y2;x3,y3"
    std::string posStr(apPosStr);
    std::stringstream ss(posStr);
    std::string token;

    while (std::getline(ss, token, ';')) {
        size_t comma = token.find(',');
        if (comma != std::string::npos) {
            double x = std::stod(token.substr(0, comma));
            double y = std::stod(token.substr(comma + 1));
            apPositions.push_back(Coord(x, y, 0));
            EV_INFO << "Loaded AP position: (" << x << ", " << y << ")" << endl;
        }
    }

    EV_INFO << "Total APs configured: " << apPositions.size() << endl;
}

double Wca::getDistanceToNearestAP()
{
    if (apPositions.empty() || !mobility) {
        return DBL_MAX;
    }

    Coord myPos = mobility->getCurrentPosition();
    double minDist = DBL_MAX;

    for (const auto& apPos : apPositions) {
        double dist = myPos.distance(apPos);
        if (dist < minDist) {
            minDist = dist;
        }
    }

    return minDist;
}

bool Wca::checkAPConnectivity()
{
    distanceToNearestAP = getDistanceToNearestAP();

    // Connected if within radio range of any AP
    // todo this would check actual signal strength
    return distanceToNearestAP <= radioRange;
}

Ipv4Address Wca::findBestGateway()
{
    Ipv4Address bestGateway;
    double bestWeight = DBL_MAX;

    // Find a clusterhead neighbor with AP connectivity (true gateway)
    for (const auto& pair : neighbors) {
        if (pair.second.hasAPConnectivity && pair.second.isClusterHead) {
            if (pair.second.weight < bestWeight) {
                bestWeight = pair.second.weight;
                bestGateway = pair.first;
            }
        }
    }

    if (!bestGateway.isUnspecified()) {
        return bestGateway;
    }

    // Find any neighbor with AP connectivity (can relay)
    bestWeight = DBL_MAX;
    for (const auto& pair : neighbors) {
        if (pair.second.hasAPConnectivity) {
            if (pair.second.weight < bestWeight) {
                bestWeight = pair.second.weight;
                bestGateway = pair.first;
            }
        }
    }

    return bestGateway;
}

void Wca::updateNetworkMode()
{
     EV_INFO << "Node " << myNodeId << " updateNetworkMode() called" << endl;

    NetworkMode oldMode = networkMode;

    hasAPConnectivity = checkAPConnectivity();
    distanceToNearestAP = getDistanceToNearestAP();

    EV_INFO << "Node " << myNodeId << " AP check: hasAP=" << hasAPConnectivity
            << ", distToAP=" << distanceToNearestAP
            << ", radioRange=" << radioRange
            << ", isCH=" << isClusterHead
            << ", members=" << clusterMembers.size() << endl;

    if (hasAPConnectivity) {
        EV_INFO << "Node " << myNodeId << " has AP, checking shouldBecomeGateway" << endl;

        if (shouldBecomeGateway()) {
            networkMode = NetworkMode::GATEWAY;
            if (oldMode != NetworkMode::GATEWAY) {
                EV_INFO << "Node " << myNodeId << " becoming GATEWAY (score="
                        << calculateGatewayScore() << ")" << endl;
                sendGatewayAnnouncement();
            }
        }
        else {
            // Direct AP access, no gateway duties
            networkMode = NetworkMode::DIRECT_AP;
        }
    }
    else {
        EV_INFO << "Node " << myNodeId << " no AP, finding gateway..." << endl;

        // No AP access - need to find a gateway
        Ipv4Address gateway = findBestGateway();
        EV_INFO << "Node " << myNodeId << " findBestGateway returned: " << gateway << endl;

        if (!gateway.isUnspecified()) {
            networkMode = NetworkMode::CLUSTER_MEMBER;
            myGateway = gateway;
        }
        else {
            if (networkMode != NetworkMode::DISCONNECTED) {
                EV_INFO << "Node " << myNodeId << " becoming DISCONNECTED, sending discovery" << endl;
                networkMode = NetworkMode::DISCONNECTED;
                myGateway = Ipv4Address::UNSPECIFIED_ADDRESS;
                sendGatewayDiscoveryRequest();
            }
        }
    }

    if (oldMode != networkMode) {
        EV_INFO << "Node " << myNodeId << " mode changed: "
                << networkModeToString(oldMode) << " -> "
                << networkModeToString(networkMode) << endl;
        updateVisualization();
    }
}
bool Wca::hasMembersOutsideAPRange()
{
    if (clusterMembers.empty()) {
        EV_INFO << "Node " << myNodeId << " hasMembersOutsideAPRange: no members" << endl;
        return false;
    }

    for (const auto& memberAddr : clusterMembers) {
        auto it = neighbors.find(memberAddr);
        if (it != neighbors.end()) {
            // Members doesn't have AP connectivity - needs gateway
            if (!it->second.hasAPConnectivity) {
                return true;
            }
        }
    }
    EV_INFO << "Node " << myNodeId << " hasMembersOutsideAPRange: NO (all members have AP)" << endl;

    return false;
}
const char* Wca::networkModeToString(NetworkMode mode)
{
    switch (mode) {
        case NetworkMode::DIRECT_AP: return "DIRECT_AP";
        case NetworkMode::GATEWAY: return "GATEWAY";
        case NetworkMode::CLUSTER_MEMBER: return "CLUSTER_MEMBER";
        case NetworkMode::DISCONNECTED: return "DISCONNECTED";
        default: return "UNKNOWN";
    }
}

void Wca::visualizeAPCoverage()
{
    if (!canvas) return;


    if (myNodeId != 0) return;

    // Clear old circles
    for (auto* circle : apRangeCircles) {
        canvas->removeFigure(circle);
        delete circle;
    }
    apRangeCircles.clear();

    // Draw coverage circle for each AP
    for (size_t i = 0; i < apPositions.size(); i++) {
        cOvalFigure *circle = new cOvalFigure(("apRange" + std::to_string(i)).c_str());
        circle->setBounds(cFigure::Rectangle(
            apPositions[i].x - radioRange,
            apPositions[i].y - radioRange,
            radioRange * 2,
            radioRange * 2));
        circle->setLineColor(cFigure::Color("blue"));
        circle->setLineWidth(2);
        circle->setLineStyle(cFigure::LINE_DASHED);
        circle->setFilled(false);
        circle->setZIndex(-1);  // Draw behind nodes
        canvas->addFigure(circle);
        apRangeCircles.push_back(circle);
    }
}

void Wca::sendGatewayAnnouncement()
{
    if (networkMode != NetworkMode::GATEWAY) {
        return;
    }

    Packet *packet = new Packet("HWCA-GATEWAY-ANNOUNCE");
    const auto& announce = makeShared<WcaPacket>();

    announce->setPacketType(WcaPacketType::GATEWAY_ANNOUNCE);
    announce->setSourceAddress(myAddress);
    announce->setDestAddress(Ipv4Address::ALLONES_ADDRESS);
    announce->setGatewayAddress(myAddress);
    announce->setNetworkMode(static_cast<int>(networkMode));
    announce->setWeight(myWeight);
    announce->setHasAPConnectivity(hasAPConnectivity);
    announce->setDistanceToAP(distanceToNearestAP);
    announce->setChunkLength(B(48));

    packet->insertAtBack(announce);

    EV_INFO << "Node " << myNodeId << " announcing GATEWAY role" << endl;

    sendPacket(packet, Ipv4Address::ALLONES_ADDRESS);
}
void Wca::processGatewayAnnouncement(const Ptr<const WcaPacket>& wcaPacket)
{
    Ipv4Address gwAddr = wcaPacket->getGatewayAddress();

    // Update neighbor info
    auto it = neighbors.find(gwAddr);
    if (it != neighbors.end()) {
        it->second.hasAPConnectivity = wcaPacket->getHasAPConnectivity();
        it->second.isClusterHead = true;  // Gateways are clusterheads
    }

    EV_INFO << "Node " << myNodeId << " received GATEWAY announcement from "
            << gwAddr << endl;

    // If a node is outside AP range and disconnected, consider joining this gateway
    if (!hasAPConnectivity && networkMode == NetworkMode::DISCONNECTED) {
        myGateway = gwAddr;
        networkMode = NetworkMode::CLUSTER_MEMBER;
        joinCluster(gwAddr);

        EV_INFO << "Node " << myNodeId << " joining gateway " << gwAddr << endl;
    }
    // If a node is a cluster member, check if this is a better gateway
    else if (networkMode == NetworkMode::CLUSTER_MEMBER) {
        if (wcaPacket->getWeight() < myWeight) {
            auto currentGW = neighbors.find(myGateway);
            if (currentGW == neighbors.end() ||
                wcaPacket->getWeight() < currentGW->second.weight) {
                myGateway = gwAddr;
                joinCluster(gwAddr);
                EV_INFO << "Node " << myNodeId << " switching to better gateway "
                        << gwAddr << endl;
            }
        }
    }

    updateVisualization();
}


void Wca::sendDataThroughGateway(Packet *packet, const Ipv4Address& finalDest)
{
    if (myGateway.isUnspecified()) {
        EV_WARN << "Node " << myNodeId << " has no gateway, dropping packet" << endl;
        delete packet;
        return;
    }

    // Create a forward wrapper packet
    Packet *fwdPacket = new Packet("HWCA-DATA-FORWARD");
    const auto& fwdHeader = makeShared<WcaPacket>();

    fwdHeader->setPacketType(WcaPacketType::DATA_FORWARD);
    fwdHeader->setSourceAddress(myAddress);
    fwdHeader->setDestAddress(myGateway);
    fwdHeader->setOriginalSource(myAddress);
    fwdHeader->setFinalDestination(finalDest);
    fwdHeader->setGatewayAddress(myGateway);
    fwdHeader->setChunkLength(B(64));

    fwdPacket->insertAtBack(fwdHeader);

    // Copy payload from original packet if any
    if (packet->getDataLength() > B(0)) {
        auto payload = packet->peekDataAt(B(0), packet->getDataLength());
        fwdPacket->insertAtBack(payload);
    }

    EV_INFO << "Node " << myNodeId << " forwarding data through gateway "
            << myGateway << " to final dest " << finalDest << endl;

    sendPacket(fwdPacket, myGateway);
    delete packet;
}


void Wca::processDataForward(Packet *packet, const Ptr<const WcaPacket>& wcaPacket)
{
    Ipv4Address originalSrc = wcaPacket->getOriginalSource();
    Ipv4Address finalDest = wcaPacket->getFinalDestination();

    EV_INFO << "Node " << myNodeId << " received DATA_FORWARD from "
            << originalSrc << " destined for " << finalDest << endl;


    if (finalDest == myAddress) {
        EV_INFO << "Node " << myNodeId << " is final destination, delivering packet from "
                << originalSrc << endl;
        metricsLogger->logPacketReceived(wcaPacket->getSequenceNumber(), myNodeId, simTime(), 1);
        return;
    }

    if (networkMode == NetworkMode::GATEWAY || networkMode == NetworkMode::DIRECT_AP) {
        if (hasAPConnectivity) {
            EV_INFO << "Gateway " << myNodeId << " forwarding to destination "
                    << finalDest << endl;

            Packet *outPacket = new Packet("HWCA-FORWARDED");
            const auto& fwdData = makeShared<WcaPacket>();

            fwdData->setPacketType(WcaPacketType::DATA_FORWARD);
            fwdData->setSourceAddress(myAddress);
            fwdData->setDestAddress(finalDest);
            fwdData->setOriginalSource(originalSrc);
            fwdData->setFinalDestination(finalDest);
            fwdData->setChunkLength(B(64));

            outPacket->insertAtBack(fwdData);

            outPacket->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::manet);
            outPacket->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

            auto addrReq = outPacket->addTagIfAbsent<L3AddressReq>();
            addrReq->setSrcAddress(L3Address(myAddress));
            addrReq->setDestAddress(L3Address(finalDest));

            outPacket->addTagIfAbsent<InterfaceReq>()->setInterfaceId(interface80211->getInterfaceId());

            send(outPacket, "ipOut");

            EV_INFO << "Gateway " << myNodeId << " forwarded packet from "
                    << originalSrc << " to " << finalDest << endl;
        }
        else {
            EV_WARN << "Gateway " << myNodeId << " lost AP connectivity!" << endl;
        }
    }
    else {
        // I'm not a gateway - forward to my gateway if I have one
        if (!myGateway.isUnspecified()) {
            EV_INFO << "Node " << myNodeId << " relaying to gateway " << myGateway << endl;
            Packet *fwdPacket = packet->dup();
            sendPacket(fwdPacket, myGateway);
        }
        else {
            EV_WARN << "Node " << myNodeId << " cannot forward - no gateway" << endl;
        }
    }
}

void Wca::sendStatusReport()
{
    Packet *packet = new Packet("HWCA-STATUS-REPORT");
    const auto& report = makeShared<WcaPacket>();

    report->setPacketType(WcaPacketType::STATUS_REPORT);
    report->setSourceAddress(myAddress);
    report->setDestAddress(serverAddress);
    report->setSequenceNumber(statusSequenceNumber++);
    report->setNetworkMode(static_cast<int>(networkMode));
    report->setIsClusterHead(isClusterHead);
    report->setClusterHeadAddress(isClusterHead ? myAddress : myClusterHead);
    report->setGatewayAddress(myGateway);
    report->setHasAPConnectivity(hasAPConnectivity);
    report->setDistanceToAP(distanceToNearestAP);
    report->setWeight(myWeight);

    // Energy level
    if (energyStorage) {
        double remaining = energyStorage->getResidualEnergyCapacity().get();
        double nominal = energyStorage->getNominalEnergyCapacity().get();
        report->setEnergyLevel(remaining / nominal);
    } else {
        report->setEnergyLevel(1.0);
    }

    // Task info todo placeholder atm
    std::ostringstream taskOss;
    taskOss << "Node" << myNodeId << "_" << networkModeToString(networkMode);
    report->setTaskInfo(taskOss.str().c_str());

    report->setTimestamp(simTime());
    report->setChunkLength(B(96));

    packet->insertAtBack(report);

    EV_INFO << "Node " << myNodeId << " sending status report #"
            << (statusSequenceNumber - 1) << " to server" << endl;

    // If we have AP connectivity, send directly otherwise use gateway
    if (hasAPConnectivity) {
        sendPacket(packet, serverAddress);
    } else if (!myGateway.isUnspecified()) {
        sendDataThroughGateway(packet, serverAddress);
    } else {
        EV_WARN << "Node " << myNodeId << " cannot send status report - no connectivity" << endl;
        delete packet;
    }
}

void Wca::processStatusReport(const Ptr<const WcaPacket>& wcaPacket)
{
	// todo server module
    EV_INFO << "Received status report from " << wcaPacket->getSourceAddress()
            << " seq=" << wcaPacket->getSequenceNumber()
            << " mode=" << wcaPacket->getNetworkMode()
            << " energy=" << wcaPacket->getEnergyLevel() << endl;
}


void Wca::processServerBroadcast(const Ptr<const WcaPacket>& wcaPacket)
{
    EV_INFO << "Node " << myNodeId << " received SERVER_BROADCAST seq="
            << wcaPacket->getSequenceNumber()
            << " command=\"" << wcaPacket->getServerCommand() << "\"" << endl;

    // todo process
    std::string command = wcaPacket->getServerCommand();

    if (command == "STATUS_REQUEST") {
        // Server requesting immediate status update
        sendStatusReport();
    }
    else if (command == "RECONFIGURE") {
        // Trigger cluster re-election
        performClusterElection();
    }
    // Add more commands as needed

    // If a node is a gateway, forward to my cluster members who don't have AP access
    if (networkMode == NetworkMode::GATEWAY) {
        for (const auto& memberAddr : clusterMembers) {
            auto it = neighbors.find(memberAddr);
            if (it != neighbors.end() && !it->second.hasAPConnectivity) {
                // Forward broadcast to this member
                Packet *fwdPacket = new Packet("HWCA-SERVER-BROADCAST-FWD");
                const auto& fwdBcast = makeShared<WcaPacket>();

                fwdBcast->setPacketType(WcaPacketType::SERVER_BROADCAST);
                fwdBcast->setSourceAddress(serverAddress);
                fwdBcast->setDestAddress(memberAddr);
                fwdBcast->setSequenceNumber(wcaPacket->getSequenceNumber());
                fwdBcast->setServerCommand(wcaPacket->getServerCommand());
                fwdBcast->setChunkLength(B(64));

                fwdPacket->insertAtBack(fwdBcast);
                sendPacket(fwdPacket, memberAddr);

                EV_INFO << "Gateway " << myNodeId << " forwarding broadcast to member "
                        << memberAddr << endl;
            }
        }
    }
}

double Wca::calculateGatewayScore()
{
    if (!hasAPConnectivity) {
        return DBL_MAX;
    }

    if (radioRange <= 0) {
        return 0.5;
    }

    double normAPDist = distanceToNearestAP / radioRange;
    if (normAPDist > 1.0) normAPDist = 1.0;

    int membersNeedingGateway = 0;
    for (const auto& memberAddr : clusterMembers) {
        auto it = neighbors.find(memberAddr);
        if (it != neighbors.end() && !it->second.hasAPConnectivity) {
            membersNeedingGateway++;
        }
    }

    double memberFactor = 1.0 / (1.0 + membersNeedingGateway);

    double mob = calculateMobility();
    double normMobility = mob / 20.0;
    if (normMobility > 1.0) normMobility = 1.0;

    double energyFactor = 0.5;
    if (energyStorage) {
        double nominal = energyStorage->getNominalEnergyCapacity().get();
        double remaining = energyStorage->getResidualEnergyCapacity().get();

        if (std::isfinite(nominal) && std::isfinite(remaining) && nominal > 0) {
            energyFactor = 1.0 - (remaining / nominal);
            if (energyFactor < 0.0) energyFactor = 0.0;
            if (energyFactor > 1.0) energyFactor = 1.0;
        }
    }

    double score = 0.4 * normAPDist +
                   0.2 * memberFactor +
                   0.2 * normMobility +
                   0.2 * energyFactor;

    return score;
}

bool Wca::shouldBecomeGateway()
{
    EV_INFO << "Node " << myNodeId << " shouldBecomeGateway() called: hasAP="
            << hasAPConnectivity << ", isCH=" << isClusterHead << endl;
    if (!hasAPConnectivity || !isClusterHead) {
        return false;
    }

    if (!hasMembersOutsideAPRange()) {
        return false;
    }

    double myScore = calculateGatewayScore();

    // Check if any neighbor would be a better gateway
    for (const auto& pair : neighbors) {
        if (pair.second.hasAPConnectivity && pair.second.gatewayScore >= 0) {
            // Neighbor is a gateway candidate
            if (pair.second.gatewayScore < myScore) {
                return false;  // Neighbor has better score
            }
            // todo better logic maybe Tie braker
            if (pair.second.gatewayScore == myScore && pair.first < myAddress) {
                return false;
            }
        }
    }

    EV_INFO << "Node " << myNodeId << " shouldBecomeGateway: YES (score=" << myScore << ")" << endl;
    return true;
}

void Wca::triggerGatewayElection()
{
    NetworkMode oldMode = networkMode;

    if (shouldBecomeGateway()) {
        if (networkMode != NetworkMode::GATEWAY) {
            networkMode = NetworkMode::GATEWAY;
            sendGatewayAnnouncement();
            EV_INFO << "Node " << myNodeId << " elected as GATEWAY (score="
                    << calculateGatewayScore() << ")" << endl;
        }
    }
    else if (hasAPConnectivity) {
        networkMode = NetworkMode::DIRECT_AP;
    }

    if (oldMode != networkMode) {
        updateVisualization();
    }
}
void Wca::sendGatewayDiscoveryRequest()
{
    if (hasAPConnectivity) {
        return;  // Don't need a gateway
    }

    Packet *packet = new Packet("HWCA-GW-DISCOVERY-REQ");
    const auto& request = makeShared<WcaPacket>();

    request->setPacketType(WcaPacketType::GATEWAY_DISCOVERY_REQUEST);
    request->setSourceAddress(myAddress);
    request->setDestAddress(Ipv4Address::ALLONES_ADDRESS);
    request->setWeight(myWeight);
    request->setChunkLength(B(32));

    packet->insertAtBack(request);

    EV_INFO << "Node " << myNodeId << " sending gateway discovery request" << endl;

    sendPacket(packet, Ipv4Address::ALLONES_ADDRESS);
}

void Wca::processGatewayDiscoveryRequest(const Ptr<const WcaPacket>& wcaPacket)
{
    Ipv4Address requesterAddr = wcaPacket->getSourceAddress();

    if (!hasAPConnectivity) {
        return;
    }

    EV_INFO << "Node " << myNodeId << " received gateway discovery from "
            << requesterAddr << ", responding" << endl;

    Packet *packet = new Packet("HWCA-GW-DISCOVERY-REPLY");
    const auto& reply = makeShared<WcaPacket>();

    reply->setPacketType(WcaPacketType::GATEWAY_DISCOVERY_REPLY);
    reply->setSourceAddress(myAddress);
    reply->setDestAddress(requesterAddr);
    reply->setGatewayAddress(myAddress);
    reply->setWeight(myWeight);
    reply->setHasAPConnectivity(true);
    reply->setDistanceToAP(distanceToNearestAP);
    reply->setIsClusterHead(isClusterHead);
    reply->setNetworkMode(static_cast<int>(networkMode));
    reply->setChunkLength(B(48));

    packet->insertAtBack(reply);

    sendPacket(packet, requesterAddr);
}

void Wca::processGatewayDiscoveryReply(const Ptr<const WcaPacket>& wcaPacket)
{
    Ipv4Address gwAddr = wcaPacket->getGatewayAddress();
    double gwWeight = wcaPacket->getWeight();
    double gwAPDist = wcaPacket->getDistanceToAP();

    EV_INFO << "Node " << myNodeId << " received gateway discovery reply from "
            << gwAddr << " (weight=" << gwWeight << ", apDist=" << gwAPDist << ")" << endl;

    // Update neighbor info
    auto it = neighbors.find(gwAddr);
    if (it != neighbors.end()) {
        it->second.hasAPConnectivity = true;
        it->second.weight = gwWeight;
        it->second.isClusterHead = wcaPacket->isClusterHead();
    }

    // If the node is disconnected or this is a better gateway, switch to it
    if (networkMode == NetworkMode::DISCONNECTED) {
        myGateway = gwAddr;
        networkMode = NetworkMode::CLUSTER_MEMBER;
        joinCluster(gwAddr);
        EV_INFO << "Node " << myNodeId << " found gateway " << gwAddr << endl;
    }
    else if (networkMode == NetworkMode::CLUSTER_MEMBER) {
        // Check if this is a better gateway
        auto currentGW = neighbors.find(myGateway);
        bool shouldSwitch = false;

        if (currentGW == neighbors.end()) {
            shouldSwitch = true;  // Current gateway gone
        }
        else if (!currentGW->second.hasAPConnectivity) {
            shouldSwitch = true;  // Current gateway lost AP
        }
        else if (gwWeight < currentGW->second.weight) {
            shouldSwitch = true;  // New gateway is better
        }

        if (shouldSwitch) {
            myGateway = gwAddr;
            joinCluster(gwAddr);
            EV_INFO << "Node " << myNodeId << " switching to better gateway " << gwAddr << endl;
        }
    }

    updateVisualization();
}
void Wca::checkGatewayHandover()
{
    // Only relevant for cluster members using a gateway
    if (networkMode != NetworkMode::CLUSTER_MEMBER || myGateway.isUnspecified()) {
        return;
    }

    // Check if current gateway is still valid
    auto currentGW = neighbors.find(myGateway);
    bool currentGWValid = (currentGW != neighbors.end() &&
                           currentGW->second.hasAPConnectivity);

    // Find best available gateway
    Ipv4Address bestGateway;
    double bestScore = DBL_MAX;

    for (const auto& pair : neighbors) {
        if (pair.second.hasAPConnectivity) {
            // Calculate a score based on weight and distance to AP
            // Lower score = better gateway
            double score = pair.second.weight;

            if (score < bestScore) {
                bestScore = score;
                bestGateway = pair.first;
            }
        }
    }

    // Decide if handover is needed
    if (!currentGWValid && !bestGateway.isUnspecified()) {
        // Current gateway lost
        EV_INFO << "Node " << myNodeId << " gateway " << myGateway
                << " lost, handing over to " << bestGateway << endl;
        performGatewayHandover(bestGateway);
    }
    else if (currentGWValid && !bestGateway.isUnspecified() && bestGateway != myGateway) {
        double currentScore = currentGW->second.weight;
        double improvement = (currentScore - bestScore) / currentScore;

        // Avoid ping-pong
        if (improvement > 0.2) {
            EV_INFO << "Node " << myNodeId << " found better gateway " << bestGateway
                    << " (improvement=" << (improvement * 100) << "%)" << endl;
            performGatewayHandover(bestGateway);
        }
    }
    else if (!currentGWValid && bestGateway.isUnspecified()) {
        // No gateway available - become disconnected
        EV_WARN << "Node " << myNodeId << " lost gateway and no alternative found" << endl;
        networkMode = NetworkMode::DISCONNECTED;
        myGateway = Ipv4Address::UNSPECIFIED_ADDRESS;
        sendGatewayDiscoveryRequest();
        updateVisualization();
    }
}

void Wca::performGatewayHandover(const Ipv4Address& newGateway)
{
    Ipv4Address oldGateway = myGateway;

    // Leave old cluster if we were a member
    if (!oldGateway.isUnspecified() && oldGateway != newGateway) {
        EV_INFO << "Node " << myNodeId << " leaving gateway " << oldGateway << endl;
    }

    // Join new gateway
    myGateway = newGateway;
    networkMode = NetworkMode::CLUSTER_MEMBER;
    joinCluster(newGateway);

    EV_INFO << "Node " << myNodeId << " completed handover to gateway " << newGateway << endl;

    updateVisualization();
}
} // namespace hwca
