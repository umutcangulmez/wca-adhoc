import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

cplusplus {{
#include "inet/common/INETDefs.h"
#include "inet/networklayer/contract/ipv4/Ipv4Address.h"
}}

namespace hwca;

enum WcaPacketType {
    HELLO = 0;
    CLUSTER_HEAD_ANNOUNCEMENT = 1;
    JOIN_REQUEST = 2;
    JOIN_REPLY = 3;
    // HWCA extensions
    GATEWAY_ANNOUNCE = 4;
    STATUS_REPORT = 5;
    SERVER_BROADCAST = 6;
    DATA_FORWARD = 7;
    GATEWAY_DISCOVERY_REQUEST = 8;
    GATEWAY_DISCOVERY_REPLY = 9;
}

class WcaPacket extends inet::FieldsChunk
{
    int packetType @enum(WcaPacketType);
    inet::Ipv4Address sourceAddress;
    inet::Ipv4Address destAddress;
    unsigned int sequenceNumber;

    // WCA parameters
    double weight;
    int nodeDegree;
    double transmissionPower;
    double mobility;
    double batteryPower;

    // Cluster information
    inet::Ipv4Address clusterHeadAddress;
    bool isClusterHead;

    simtime_t timestamp;

    bool hasAPConnectivity = false;      // Whether sender can reach an AP
    double distanceToAP = -1;            // Distance to nearest AP
    // HWCA Gateway/Server fields
    int networkMode = 0;                 // NetworkMode enum value
    inet::Ipv4Address gatewayAddress;    // Gateway for forwarding


    double gatewayScore = -1;           // Gateway election score (-1 = not a gateway candidate)

    // Status report fields (robot -> server)
    double energyLevel = 1.0;
    string taskInfo = "";

    // Server broadcast fields (server -> robots)
    string serverCommand = "";

    // Data forwarding fields
    inet::Ipv4Address originalSource;
    inet::Ipv4Address finalDestination;


}