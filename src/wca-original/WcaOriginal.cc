#include "Wca.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/common/Ptr.h"

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

        // Schedule first hello with random offset to avoid collisions
        scheduleAt(simTime() + uniform(0, 0.1), helloTimer);
        scheduleAt(simTime() + clusterTimeout, clusterTimer);
        scheduleAt(simTime() + 5.0, metricTimer);  // Start logging at 5s

        // Beware that at startup, every node initially becomes a standalone clusterhead
        isClusterHead = true;
        myClusterHead = myAddress;
        lastCHStartTime = simTime();
        metricsLogger->logBecomeCH(simTime());
        EV_INFO << "Node " << myNodeId << " starting as initial CH" << endl;
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

    // Update status text (CH/Member)
    if (!statusText) {
        statusText = new cTextFigure("statusText");
        canvas->addFigure(statusText);
    }

    if (isClusterHead) {
        std::ostringstream statusOss;
        statusOss << "CH(" << clusterMembers.size() << ")";
        statusText->setText(statusOss.str().c_str());
        statusText->setColor(cFigure::Color("red"));
    } else if (!myClusterHead.isUnspecified()) {
        std::ostringstream chOss;
        chOss << "->N" << getNodeIdFromAddress(myClusterHead);
        statusText->setText(chOss.str().c_str());
        statusText->setColor(cFigure::Color("green"));
    } else {
        statusText->setText("?");
        statusText->setColor(cFigure::Color("gray"));
    }
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

    EV_DEBUG << "Node " << myNodeId << " received HELLO from " << srcAddr
             << ", weight=" << wcaPacket->getWeight()
             << ", isCH=" << wcaPacket->isClusterHead() << endl;
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
    // Original WCA formula from Chatterjee, Das, Turgut (2002):
    int degree = getNodeDegree();
    double sumDistances = getSumOfDistances();
    double mob = calculateMobility();
    double chTime = getCumulativeCHTime();

    double degreeDiff = std::abs(degree - idealDegree);

    // Normalize factors to [0, ]
    double normDegreeDiff = std::min(degreeDiff / (double)idealDegree, 1.0);
    double normSumDistances = std::min(sumDistances / (radioRange * idealDegree), 1.0);
    double normMobility = std::min(mob / 20.0, 1.0);
    double normCHTime = std::min(chTime / 100.0, 1.0);

    // Lower weight = better CH candidate
    double weight = degreeWeight * normDegreeDiff +
                    distanceWeight * normSumDistances +
                    mobilityWeight * normMobility +
                    clusterHeadTimeWeight * normCHTime;

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

	// Log sent packet
    metricsLogger->logPacketSent(packetId, myNodeId, destAddr.getInt(), simTime());

	// Initialize hopCount if missing
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
    const auto& networkHeader = packet->peekAtFront<Ipv4Header>();

    if (networkHeader->getProtocol() == &Protocol::manet) {
        EV_INFO << "WCA packet received\n";
        take(packet);
        handleMessage(packet);
        return STOLEN;
    }
    else if (networkHeader->getProtocol() == &Protocol::udp) {
        int packetId = packetIdCounter++;
        forwardDataPacket(packet, packetId);
        return STOLEN;
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
        default:
            EV_WARN << "Unknown WCA packet type" << endl;
            break;
    }
}

void Wca::forwardDataPacket(Packet *packet)
{
    Enter_Method("forwardDataPacket");

    auto ipv4Header = packet->peekAtFront<Ipv4Header>();
    Ipv4Address dest = ipv4Header->getDestAddress();
    Ipv4Address source = ipv4Header->getSrcAddress();
    Ipv4Address nextHop;

    int packetId = packetIdCounter++;

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

    // Update hop count
    hopCount++;
    packet->par("hopCount") = hopCount;

    // Remove old IPv4 header and recreate
    packet->popAtFront<Ipv4Header>();

    // Create new IPv4 header
    auto newHeader = makeShared<Ipv4Header>();
    newHeader->setSrcAddress(source);
    newHeader->setDestAddress(dest);
    newHeader->setProtocol(&Protocol::udp);
    newHeader->setTimeToLive(64);
    newHeader->setIdentification(packetId);

    packet->insertAtFront(newHeader);
    sendPacket(packet, nextHop);
}

void Wca::finish()
{
    EV_INFO << "WCA finish - isClusterHead: " << isClusterHead
            << ", neighbors: " << neighbors.size()
            << ", members: " << clusterMembers.size() << "\n";
    metricsLogger->finalizeAndClose();
    delete metricsLogger;
}

} // namespace hwca