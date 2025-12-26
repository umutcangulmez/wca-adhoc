package hwca.wca;

import inet.applications.contract.IApp;

simple Wca like IApp
{
    parameters:
        @class(hwca::Wca);
        @display("i=block/network2");
        
        // Module references
        string interfaceTableModule = default("^.interfaceTable");
        string routingTableModule = default("^.ipv4.routingTable");
        string networkProtocolModule = default("^.ipv4.ip");
        
        // Timing parameters
        double helloInterval @unit(s) = default(2s);
        double clusterTimeout @unit(s) = default(6s);
        
        // Radio parameters
        double maxTransmissionPower @unit(mW) = default(100mW);
        double radioRange @unit(m) = default(250m);
        
        // w1: Degree difference weight
        double degreeWeight = default(0.15);
        // w2: Sum of distances weight
        double distanceWeight = default(0.15);
        // w3: Mobility weight
        double mobilityWeight = default(0.20);
        // w4: Cumulative CH time weight
        double clusterHeadTimeWeight = default(0.20);

        // HWCA Infrastructure parameters
        double apDistanceWeight = default(0.30);       // w5: weight for AP distance
        double apSignalThreshold = default(-75);       // AP signal threshold in dBm
        string apPositions = default("");              // AP positions as "x1,y1;x2,y2;..."
        // ideal number of neighbors
        int idealDegree = default(5);
        
        // Statistics signals
        @signal[clusterHeadChanged](type=bool);
        @signal[nodeWeight](type=double);
        @signal[neighborCount](type=long);
        
        @statistic[clusterHeadChanged](title="Cluster Head Status Changes"; source=clusterHeadChanged; record=count,vector);
        @statistic[nodeWeight](title="Node Weight"; source=nodeWeight; record=stats,vector);
        @statistic[neighborCount](title="Neighbor Count"; source=neighborCount; record=stats,vector);
        
    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
        input ipIn;
        output ipOut;
}