package hwca.simulations;

import inet.node.inet.AdhocHost;
import hwca.wca.Wca;

module WcaHost extends AdhocHost
{
    parameters:
        @display("i=device/robot");

    submodules:
        wca: Wca {
            @display("p=825,226");
        }

    connections:
        wca.ipOut --> tn.in++;
        wca.ipIn <-- tn.out++;
}