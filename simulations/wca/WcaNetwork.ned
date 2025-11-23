package hwca.simulations;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.AdhocHost;
import inet.node.wireless.AccessPoint;
import inet.node.inet.Router;
import inet.node.ethernet.Eth100M;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

network WcaNetwork
{
    parameters:
        int numHosts = default(5);
        int numAps = default(2);
        @display("bgb=1200,800");

    submodules:


        configurator: Ipv4NetworkConfigurator {
            @display("p=100,150");
        }

        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=100,250");
        }

        // Mobile robots with WCA clustering
        host[numHosts]: WcaHost {
            @display("i=device/robot");
        }

        // Access Points (stationary)
        ap0: AccessPoint {
            @display("p=100,200;i=device/accesspoint");
        }

        ap1: AccessPoint {
            @display("p=300,500;i=device/accesspoint");
        }

        // Router (connects APs)
        router: Router {
            @display("p=600,100;i=abstract/router");
        }

    connections:
        // Connect APs to router via ethernet
        ap0.ethg++ <--> Eth100M <--> router.ethg++;
        ap1.ethg++ <--> Eth100M <--> router.ethg++;
}