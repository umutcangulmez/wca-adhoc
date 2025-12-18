package hwca.simulations;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

network WcaNetwork
{
    parameters:
        int numHosts = default(10);
        @display("bgb=1200,800");

    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,150");
        }

        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=100,250");
        }

        // Mobile ad-hoc nodes with WCA clustering
        host[numHosts]: WcaHost {
            @display("i=device/robot");
        }
}