# Ethereum Transaction Observatory

## Overview
This project aims to build a Low-Latency Ethereum Node for Event Monitoring.  
Rather than executing or simulating transactions, the focus is on **observing** the network and **gathering detailed statistics** about pending transactions in the mempool.

## Goals

- Detect and decode transactions as soon as they appear on the network.  
- Track transaction behaviour from arrival to inclusion or drop.  
- Study propagation, eviction, and replacement patterns across peers.

### Learning Objectives
- Implement Ethereum’s discovery and gossip mechanisms in Go.  
- Improve my understanding of the Ethereum P2P stack (devp2p / RLPx / eth).  
- Get better at data collection, visualisation, and presentation.


## Statistics Tracked

| Metric | Description |
|--------|--------------|
| **Dropped / Evicted Rate** | Transactions that never reach inclusion. |
| **Transaction Types** | Categorisation of pending transactions. |
| **Time in Pool** | From first observation to inclusion or drop. |
| **Self Front-Running** | Replacement of own transactions by higher-fee versions. |

Future metrics: propagation speed, replacement rate, MEV-related effects, peer coverage.

## Issues & Next Steps

- My node currently receives transactions **only from peers**, not users — leading to potential sampling bias.  
  → Possible fix: advertise a small endpoint (e.g. `rpc.[something].com`) to receive user-submitted TXs.  
- Investigate peer behaviour to avoid being disconnected (do I need to relay blocks / TXs?).


## Roadmap

- [x] Implement discv4 node discovery  
- [x] Implement RLPx handshake and frame exchange  
- [x] Receive and decode gossip transactions  
- [ ] Gather transaction lifecycle statistics  
- [ ] Visualise results  
- [ ] (Optional) Paper / presentation


## Legacy Work: ETH Discover

Originally, this project aimed to implement a **full Ethereum node** capable of syncing from genesis via custom implementations of  
[discv4](https://github.com/ethereum/devp2p/blob/master/discv4.md),  
[RLPx](https://github.com/ethereum/devp2p/blob/master/rlpx.md), and  
[eth/wire](https://github.com/ethereum/devp2p/blob/master/caps/eth.md).  

That groundwork remains valuable for understanding Ethereum’s network layer and continues to inform the current direction.