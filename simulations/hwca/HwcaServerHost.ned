package hwca.simulations;

import inet.node.inet.AdhocHost;
import hwca.wca.HwcaServer;

module HwcaServerHost extends AdhocHost
{
    parameters:
        @display("i=device/server");
        hasStatus = default(true);

    submodules:
        hwcaServer: HwcaServer {
            parameters:
                interfaceTableModule = "^.interfaceTable";
                routingTableModule = "^.ipv4.routingTable";
                networkProtocolModule = "^.ipv4.ip";
            @display("p=825,226");
        }

    connections:
        hwcaServer.ipOut --> tn.in++;
        hwcaServer.ipIn <-- tn.out++;
        hwcaServer.socketOut --> at.in++;
        hwcaServer.socketIn <-- at.out++;
}