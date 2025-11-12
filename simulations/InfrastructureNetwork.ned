package hwca.simulations;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.WirelessHost;
import inet.node.wireless.AccessPoint;
import inet.node.inet.Router;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211RadioMedium;
import ned.DatarateChannel;

network InfrastructureNetwork
{
    parameters:
        int numHosts = default(5);
        @display("bgb=800,500");
    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=50,50");
        }
        ap1: AccessPoint {
            @display("p=200,150;i=device/accesspoint");
        }
        ap2: AccessPoint {
            @display("p=600,150;i=device/accesspoint");
        }
        router: Router {
            @display("p=400,300");
        }
        host[numHosts]: WirelessHost {
            @display("p=200+100*index,400;i=device/laptop");
        }
        radioMedium: Ieee80211RadioMedium {
        @display("p=200,50");
 		}

    connections allowunconnected:
        ap1.ethg++ <--> DatarateChannel { datarate = 100Mbps; delay = 0.1us; }<--> router.ethg++;
        ap2.ethg++ <--> DatarateChannel { datarate = 100Mbps; delay = 0.1us; } <--> router.ethg++;
}