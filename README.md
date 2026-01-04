# Hybrid Weighted Clustering Algorithm (HWCA)

An infrastructure-aware clustering algorithm for mobile ad-hoc networks in warehouse robotics environments, implemented in OMNeT++ with INET framework.

## About

This project extends the classic Weighted Clustering Algorithm (WCA) to maintain connectivity between mobile robots and a centralized server, even when robots move outside access point coverage.

**Problem**: Mobile robots in warehouses lose connection to fleet management servers when they move into areas without AP coverage.

**Solution**: HWCA enables robots to relay messages through neighboring robots that have AP access (gateway mechanism).

## My Contribution

- Implemented the original WCA algorithm from scratch as a baseline
- Extended WCA with a new **AP distance weight component** to prefer nodes closer to access points as cluster heads
- Designed a **four-mode system** (DIRECT_AP, GATEWAY, CLUSTER_MEMBER, DISCONNECTED) for seamless infrastructure/ad-hoc switching
- Implemented **gateway forwarding** mechanism for robots outside AP range
- Added **centralized server integration** for real-time fleet monitoring

## Requirements

- OMNeT++ 6.2.0
- INET Framework 4.5.4

## Project Structure

```
wca-adhoc/
├── src/
│   ├── wca/          # Original WCA implementation (baseline)
│   └── hwca/         # HWCA implementation (main contribution)
└── simulations/      # Network configurations and scenarios
```



## References

M. Chatterjee, S. K. Das, and D. Turgut, "WCA: A Weighted Clustering Algorithm for Mobile Ad Hoc Networks," *Cluster Computing*, vol. 5, no. 2, pp. 193-204, 2002.

## Author

Umut Can Gülmez  
CENG797 Term Project - METU, Fall 2025-2026