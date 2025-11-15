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
        myWeight = 0.0;
        lastMobilityUpdate = simTime();

        // Initialize timers
        helloTimer = new cMessage("helloTimer");
        clusterTimer = new cMessage("clusterTimer");

        // Initialize signal
        clusterHeadChangedSignal = registerSignal("clusterHeadChanged");
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

        // Todo Try to get energy storage (optional)
        cModule *host = getContainingNode(this);
        energyStorage = dynamic_cast<power::IEpEnergyStorage *>(
            host->getSubmodule("energyStorage"));

        // Register netfilter hook
        INetfilter *netfilter = getModuleFromPar<INetfilter>(par("networkProtocolModule"), this);
        netfilter->registerHook(0, this);

        // Schedule first hello
        scheduleAt(simTime() + uniform(0, 0.1), helloTimer);
        scheduleAt(simTime() + clusterTimeout, clusterTimer);
    }
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
            scheduleAt(simTime() + clusterTimeout, clusterTimer);
        }
    }
    else {
        Packet *packet = check_and_cast<Packet *>(msg);
        auto wcaPacket = packet->peekAtFront<WcaPacket>();

        switch (wcaPacket->getPacketType()) {
            case WcaPacketType::HELLO:
                processHelloPacket(packet);
                break;
            case WcaPacketType::CLUSTER_HEAD_ANNOUNCEMENT:
                processCHAnnouncement(packet);
                break;
            case WcaPacketType::JOIN_REQUEST:
                processJoinRequest(packet);
                break;
            case WcaPacketType::JOIN_REPLY:
                processJoinReply(packet);
                break;
            default:
                EV_WARN << "Unknown packet type received\n";
                break;
        }
        delete packet;
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
}

double Wca::calculateWeight()
{
    double degree = getNodeDegree();
    double txPower = maxTransmissionPower;
    double mob = calculateMobility();
    double battery = getBatteryLevel();

    // Normalize values
    double normDegree = degree / 10.0;  // Assume max 10 neighbors for now
    double normTxPower = txPower / maxTransmissionPower;
    double normMobility = std::min(mob / 10.0, 1.0);  // Assume max 10 m/s
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
        return energyStorage->getResidualEnergyCapacity().get() /
               energyStorage->getNominalEnergyCapacity().get();
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
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::manet);
    packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
    packet->addTagIfAbsent<L3AddressReq>()->setDestAddress(destAddr);
    packet->addTagIfAbsent<L3AddressReq>()->setSrcAddress(myAddress);
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

    return ACCEPT;
}

void Wca::finish()
{
    EV_INFO << "WCA finish - isClusterHead: " << isClusterHead
            << ", neighbors: " << neighbors.size()
            << ", members: " << clusterMembers.size() << "\n";
}

} // namespace hwca
