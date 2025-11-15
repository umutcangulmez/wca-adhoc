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
}

class WcaPacket extends inet::FieldsChunk
{
    int packetType @enum(WcaPacketType);
    inet::Ipv4Address sourceAddress;
    inet::Ipv4Address destAddress;

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
}