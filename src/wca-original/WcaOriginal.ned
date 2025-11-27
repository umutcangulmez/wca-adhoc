package hwca.wca;

import inet.routing.contract.IManetRouting;

simple Wca like IManetRouting
{
    parameters:
        @display("i=block/network2");
        @class(hwca::Wca);

        // Interface parameters
        string interfaceTableModule;
        string routingTableModule = default("^.ipv4.routingTable");
        string networkProtocolModule = default("^.ipv4.ip");

        // WCA specific parameters
        double helloInterval @unit(s) = default(1s);
        double clusterTimeout @unit(s) = default(3s);
        double maxTransmissionPower @unit(mW) = default(100mW);

        string serverAddress = default("10.0.0.1");

        // Weight factors (should sum to 1.0)
        double degreeWeight = default(0.25);
        double transmissionWeight = default(0.25);
        double mobilityWeight = default(0.25);
        double batteryWeight = default(0.25);

        // Radio range for neighbor detection
        double radioRange @unit(m) = default(250m);

        @signal[clusterHeadChanged](type=bool);
        @statistic[isClusterHead](source=clusterHeadChanged; record=vector,stats; interpolationmode=sample-hold);

    gates:
        input ipIn;
        output ipOut;
}