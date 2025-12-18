package hwca.simulations;

import inet.node.inet.AdhocHost;
import hwca.wca.Wca;

module WcaHost extends AdhocHost
{
    parameters:
        @display("i=device/robot");
        hasStatus = default(true);
    submodules:
        wca: Wca {
            parameters:
                interfaceTableModule = "^.interfaceTable";
                routingTableModule = "^.ipv4.routingTable";
                networkProtocolModule = "^.ipv4.ip";
            @display("p=825,226");
        }

    connections:
        wca.ipOut --> tn.in++;
        wca.ipIn <-- tn.out++;
        wca.socketOut --> at.in++;
        wca.socketIn <-- at.out++;
}