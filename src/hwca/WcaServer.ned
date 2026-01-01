package hwca.wca;

import inet.applications.contract.IApp;

simple HwcaServer like IApp
{
    parameters:
        @class(hwca::HwcaServer);
        @display("i=device/server");

        // Module references
        string interfaceTableModule = default("^.interfaceTable");
        string routingTableModule = default("^.ipv4.routingTable");
        string networkProtocolModule = default("^.ipv4.ip");

        // Server parameters
        double broadcastInterval @unit(s) = default(10s);
        double robotTimeoutThreshold @unit(s) = default(15s);
        int expectedRobotCount = default(10);

        // Statistics
        @signal[robotStatusReceived](type=long);
        @signal[robotDisconnected](type=long);
        @signal[connectedRobotCount](type=long);

        @statistic[robotStatusReceived](title="Status Reports Received"; source=robotStatusReceived; record=count,vector);
        @statistic[robotDisconnected](title="Robot Disconnections"; source=robotDisconnected; record=count,vector);
        @statistic[connectedRobotCount](title="Connected Robot Count"; source=connectedRobotCount; record=stats,vector);

    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
        input ipIn;
        output ipOut;
}