#ifndef WCAMETRICSLOGGER_H_
#define WCAMETRICSLOGGER_H_

#include <omnetpp.h>
#include <fstream>
#include <map>
#include <vector>

using namespace omnetpp;

class WCAMetricsLogger {
private:
  std::ofstream logFile;
  std::ofstream csvFile;

  // Metrics tracking
  int totalPacketsSent;
  int totalPacketsReceived;
  int totalPacketsDropped;
  int totalRoutingOverhead;

  std::map<int, double> packetDelays;
  std::map<int, int> hopCounts;
  std::map<int, std::vector<int>> routePaths;

  double totalEnergyConsumed;
  int clusterHeadChanges;
  int totalClusterFormed;

  simtime_t simulationStartTime;
  simtime_t lastLogTime;

public:
  WCAMetricsLogger();
  ~WCAMetricsLogger();

  void initialize(const char* logFileName, const char* csvFileName);
  void logPacketSent(int packetId, int sourceNode, int destNode, simtime_t timestamp);
  void logPacketReceived(int packetId, int destNode, simtime_t timestamp, int hopCount);
  void logPacketDropped(int packetId, int nodeId, const char* reason, simtime_t timestamp);
  void logRoutingOverhead(int controlPackets);
  void logClusterFormation(int numClusters, std::vector<int> clusterHeads);
  void logEnergyConsumption(int nodeId, double energy);
  void logRoutePath(int packetId, std::vector<int> path);

  void calculateAndLogMetrics(simtime_t currentTime);
  void finalizeAndClose();

  // Getters for analysis
  double getAverageDelay();
  double getPacketDeliveryRatio();
  double getAverageHopCount();
  double getThroughput(simtime_t duration);
  double getRoutingOverheadRatio();
};

#endif
