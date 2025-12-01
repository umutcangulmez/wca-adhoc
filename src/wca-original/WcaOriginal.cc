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
        transmissionWeight = par("transmissionWeight");
        mobilityWeight = par("mobilityWeight");
        batteryWeight = par("batteryWeight");
        radioRange = par("radioRange");

        // Initialize state
        isClusterHead = false;
        lastMobilityUpdate = simTime();

        // Initialize timers
        helloTimer = new cMessage("helloTimer");
        clusterTimer = new cMessage("clusterTimer");
        metricTimer = new cMessage("metricTimer");

        // Initialize metric logger
        metricsLogger = new WCAMetricsLogger();
        std::string nodeId = std::to_string(getContainingNode(this)->getIndex());
        std::string logFile = "results/wca_performance_node" + nodeId + ".log";
        std::string csvFile = "results/wca_metrics_node" + nodeId + ".csv";
        metricsLogger->initialize(logFile.c_str(), csvFile.c_str());

        // Schedule periodic metric calculation
        packetIdCounter = 0;

        // Initialize signal
        clusterHeadChangedSignal = registerSignal("clusterHeadChanged");
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

        // Get mobility module
        mobility = check_and_cast<IMobility *>(getParentModule()->getSubmodule("mobility"));
        previousPosition = mobility->getCurrentPosition();

        // Try to get energy storage
        cModule *host = getContainingNode(this);
        energyStorage = dynamic_cast<power::IEpEnergyStorage *>(
            host->getSubmodule("energyStorage"));

        // Register netfilter hook
        INetfilter *netfilter = getModuleFromPar<INetfilter>(par("networkProtocolModule"), this);
        netfilter->registerHook(0, this);

        // Calculate initial weight
        myWeight = calculateWeight();
        EV_INFO << "Initial weight of node " << myAddress << " = " << myWeight << endl;

        // Schedule first hello with random offset to avoid collisions
        scheduleAt(simTime() + uniform(0, 0.1), helloTimer);
        scheduleAt(simTime() + clusterTimeout, clusterTimer);
        scheduleAt(simTime() + 10.0, metricTimer);
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
            metricsLogger->calculateAndLogMetrics(simTime());
            scheduleAt(simTime() + 10.0, msg);
        }
    }
    else {
        Packet *packet = check_and_cast<Packet *>(msg);
        auto ipv4Header = packet->popAtFront<inet::Ipv4Header>();
        int hopCount = 0;

        const Ptr<const WcaPacket> wcaPacket = packet->peekAtFront<WcaPacket>();
        if (!wcaPacket) {
            metricsLogger->logPacketReceived(packetIdCounter++, getContainingNode(this)->getIndex(),
                                             simTime(), hopCount);
            return;
        }
        switch (wcaPacket->getPacketType()) {
            case WcaPacketType::HELLO:
                processHelloPacket(packet);
                metricsLogger->logRoutingOverhead(1);
                break;
            case WcaPacketType::CLUSTER_HEAD_ANNOUNCEMENT:
                processCHAnnouncement(packet);
                metricsLogger->logRoutingOverhead(1);
                break;
            case WcaPacketType::JOIN_REQUEST:
                processJoinRequest(packet);
                metricsLogger->logRoutingOverhead(1);
                break;
            case WcaPacketType::JOIN_REPLY:
                processJoinReply(packet);
                metricsLogger->logRoutingOverhead(1);
                break;
            default:
                EV_WARN << "Unknown packet type received\n";
                metricsLogger->logPacketDropped(0, getContainingNode(this)->getIndex(),
                                              "Unknown packet type", simTime());
                break;
        }
    }
}

void Wca::sendHelloPacket()
{
    Packet *packet = new Packet("WCA-HELLO");
    const auto& hello = makeShared<WcaPacket>();

    hello->setPacketType(WcaPacketType::HELLO);
    hello->setSourceAddress(myAddress);
    hello->setDestAddress(Ipv4Address::ALLONES_ADDRESS);
    hello->setWeight(calculateWeight());
    hello->setNodeDegree(getNodeDegree());
    hello->setTransmissionPower(maxTransmissionPower);
    hello->setMobility(calculateMobility());
    hello->setBatteryPower(getBatteryLevel());
    hello->setIsClusterHead(isClusterHead);
    hello->setClusterHeadAddress(isClusterHead ? myAddress : myClusterHead);
    hello->setTimestamp(simTime());
    hello->setChunkLength(B(64));

    packet->insertAtBack(hello);
    packet->addPar("hopCount") = 0;
    sendPacket(packet, Ipv4Address::ALLONES_ADDRESS);
}

void Wca::processHelloPacket(Packet *packet)
{
    auto wcaPacket = packet->peekAtFront<WcaPacket>();
    auto srcAddr = wcaPacket->getSourceAddress();

    if (srcAddr == myAddress)
        return;

    updateNeighborInfo(wcaPacket, srcAddr);
}

void Wca::performClusterElection()
{
    myWeight = calculateWeight();
    bool shouldBeClusterHead = true;

    // Check if any neighbor has lower weight
    for (const auto& pair : neighbors) {
        if (pair.second.weight < myWeight) {
            shouldBeClusterHead = false;
            break;
        }
    }

    // If no neighbors, become cluster head by default
    if (neighbors.empty()) {
        EV_INFO << "Node " << myAddress << " has no neighbors, becoming isolated CH\n";
        shouldBeClusterHead = true;
    }

    if (shouldBeClusterHead && !isClusterHead) {
        becomeClusterHead();
    }
    else if (!shouldBeClusterHead && isClusterHead) {
        isClusterHead = false;
        clusterMembers.clear();
        emit(clusterHeadChangedSignal, false);

        // Find best cluster head to join
        Ipv4Address bestCH;
        double minWeight = myWeight;

        for (const auto& pair : neighbors) {
            if (pair.second.weight < minWeight) {
                minWeight = pair.second.weight;
                bestCH = pair.first;
            }
        }

        if (!bestCH.isUnspecified()) {
            joinCluster(bestCH);
        }
    }
    else if (shouldBeClusterHead && isClusterHead) {
        std::vector<int> chList;
        chList.push_back(getContainingNode(this)->getIndex());

        metricsLogger->logClusterFormation(1, chList);
        EV_INFO << "Node " << getContainingNode(this)->getIndex()
                << " remains CH with " << clusterMembers.size() << " members\n";
    }
}

double Wca::calculateWeight()
{
    double degree = getNodeDegree();
    double txPower = maxTransmissionPower;
    double mob = calculateMobility();
    double battery = getBatteryLevel();

    // Normalize values
    double normDegree = degree / 10.0;  // Assume max 10 neighbors todo retrieve this from params
    double normTxPower = txPower / maxTransmissionPower;
    double normMobility = std::min(mob / 10.0, 1.0);  // Assume max 10 m/s todo retrieve this from params
    double normBattery = battery;

    // Calculate weighted sum (lower is better)
    double weight = degreeWeight * (1.0 - normDegree) +
                    transmissionWeight * normTxPower +
                    mobilityWeight * normMobility +
                    batteryWeight * (1.0 - normBattery);

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

double Wca::getBatteryLevel()
{
    if (energyStorage) {
        double currentEnergy = energyStorage->getResidualEnergyCapacity().get();
        double nominalEnergy = energyStorage->getNominalEnergyCapacity().get();
        double consumed = nominalEnergy - currentEnergy;

        static simtime_t lastEnergyLog = 0;
        if (simTime() - lastEnergyLog > 5.0) {  // Log every 5 seconds
            metricsLogger->logEnergyConsumption(getContainingNode(this)->getIndex(), consumed);
            lastEnergyLog = simTime();
        }

        return currentEnergy / nominalEnergy;
    }
    return 1.0;  // Full battery if no energy model
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

void Wca::becomeClusterHead()
{
    isClusterHead = true;
    myClusterHead = myAddress;
    emit(clusterHeadChangedSignal, true);

    EV_INFO << "Node " << myAddress << " became cluster head\n";

    // Send announcement
    Packet *packet = new Packet("WCA-CH-ANNOUNCE");
    const auto& announce = makeShared<WcaPacket>();

    announce->setPacketType(WcaPacketType::CLUSTER_HEAD_ANNOUNCEMENT);
    announce->setSourceAddress(myAddress);
    announce->setDestAddress(Ipv4Address::ALLONES_ADDRESS);
    announce->setClusterHeadAddress(myAddress);
    announce->setIsClusterHead(true);
    announce->setChunkLength(B(32));

    packet->insertAtBack(announce);
    sendPacket(packet, Ipv4Address::ALLONES_ADDRESS);
}

void Wca::joinCluster(const Ipv4Address& chAddress)
{
    myClusterHead = chAddress;

    EV_INFO << "Node " << myAddress << " joining cluster headed by " << chAddress << "\n";

    // Send join request
    Packet *packet = new Packet("WCA-JOIN-REQ");
    const auto& joinReq = makeShared<WcaPacket>();

    joinReq->setPacketType(WcaPacketType::JOIN_REQUEST);
    joinReq->setSourceAddress(myAddress);
    joinReq->setDestAddress(chAddress);
    joinReq->setClusterHeadAddress(chAddress);
    joinReq->setChunkLength(B(32));

    packet->insertAtBack(joinReq);
    sendPacket(packet, chAddress);
}

void Wca::processCHAnnouncement(Packet *packet)
{
    auto wcaPacket = packet->peekAtFront<WcaPacket>();
    auto chAddr = wcaPacket->getClusterHeadAddress();

    if (!isClusterHead && myClusterHead.isUnspecified()) {
        joinCluster(chAddr);
    }
}

void Wca::processJoinRequest(Packet *packet)
{
    if (!isClusterHead)
        return;

    auto wcaPacket = packet->peekAtFront<WcaPacket>();
    auto memberAddr = wcaPacket->getSourceAddress();

    clusterMembers.insert(memberAddr);

    EV_INFO << "Node " << memberAddr << " joined cluster\n";

    // Send join reply
    Packet *replyPacket = new Packet("WCA-JOIN-REPLY");
    const auto& joinReply = makeShared<WcaPacket>();

    joinReply->setPacketType(WcaPacketType::JOIN_REPLY);
    joinReply->setSourceAddress(myAddress);
    joinReply->setDestAddress(memberAddr);
    joinReply->setClusterHeadAddress(myAddress);
    joinReply->setChunkLength(B(32));

    replyPacket->insertAtBack(joinReply);
    sendPacket(replyPacket, memberAddr);
}

void Wca::processJoinReply(Packet *packet)
{
    auto wcaPacket = packet->peekAtFront<WcaPacket>();
    myClusterHead = wcaPacket->getClusterHeadAddress();

    EV_INFO << "Join confirmed by cluster head " << myClusterHead << "\n";
}

void Wca::sendPacket(Packet *packet, const Ipv4Address& destAddr)
{
    Enter_Method_Silent();
    take(packet);

    // Assign packet ID for metrics
    int packetId = packetIdCounter++;

    // Log sent packet
    metricsLogger->logPacketSent(packetId, getContainingNode(this)->getIndex(), destAddr.getInt(), simTime());

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

void Wca::forwardDataPacket(Packet *packet, int packetId)
{
    Enter_Method_Silent();
    take(packet);

    auto ipv4Header = packet->peekAtFront<Ipv4Header>();
    Ipv4Address dest = ipv4Header->getDestAddress();
    Ipv4Address source = ipv4Header->getSrcAddress();
    Ipv4Address nextHop;

    // Initialize hop count if it doesn't exist
    int hopCount = 0;
    if (packet->hasPar("hopCount")) {
        hopCount = packet->par("hopCount").longValue();
    } else {
        packet->addPar("hopCount") = 0;
    }

    if (dest == myAddress) {
        EV_INFO << "Packet reached destination " << myAddress << "\n";
        metricsLogger->logPacketReceived(packetId, getContainingNode(this)->getIndex(), simTime(), hopCount);
        delete packet;
        return;
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
        EV_WARN << "No route to destination " << dest << ", dropping packet\n";
        metricsLogger->logPacketDropped(packetId, getContainingNode(this)->getIndex(),
                                       "No route", simTime());
        delete packet;
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