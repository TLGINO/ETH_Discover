# Ethereum Transaction Observatory

## Overview
This project aims to build a ~Custom Ethereum Node for Mempool TX Monitoring.  
Rather than executing or simulating transactions, the focus is on **observing** the network and **gathering detailed statistics** about pending transactions in the mempool.

## Goals
- Detect transactions as soon as they arrive in the mempool.
- Track transaction behaviour from arrival to inclusion or drop (does not need to be live - can be post-facto).
- Get mempool transaction statistics: dropped / included / low value / DDOS / spam / smart contracts etc
- Get high mempool coverage (currently ~20%, goal 80%)

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
| **Block coverage** | Percentage of transactions seen vs what was included in the block. |


## Issues & Next Steps

- My node currently receives transactions **only from peers**, not users — leading to potential sampling bias.  
  → Possible fix: advertise a small endpoint (e.g. `rpc.[something].com`) to receive user-submitted TXs.  
- Investigate peer behaviour to avoid being disconnected / receive more transactions (do I need to also relay blocks?).
- Increase block coverage

## Roadmap

- [x] Implement discv4 node discovery  
- [x] Implement RLPx handshake and frame exchange  
- [x] Receive and decode gossip transactions  
- [x] Gather transaction lifecycle statistics  
- [x] Visualise results  
- [] Improve block coverage
- [ ] (Optional) Paper / presentation


## Some useful links:

This is what was followed in order to create the node - these are the specs / instructions.
[discv4](https://github.com/ethereum/devp2p/blob/master/discv4.md),  
[RLPx](https://github.com/ethereum/devp2p/blob/master/rlpx.md), and  
[eth/wire](https://github.com/ethereum/devp2p/blob/master/caps/eth.md).  