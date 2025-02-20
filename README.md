# ETH Discover

## IDEA:

This project aims to create a simple ethereum node, capable of connecting to the network and syncing from GENESIS to the HEAD.

TBD: The data will be stored in some sort of database to enable super-fast querying.

## So far:
There are ~3 milestone needed in order to sync:
 - Discovery: find ethereum nodes to connect to
 - RLPx: establish a secure connection to ethereum nodes
 - Eth/Wire: request block data from ethereum nodes

### Discovery:
Discovery seems to work very well. By recursively connecting to nodes and requesting eth peers (IPs / ports), I am able to connect to upwards of 2k nodes (after which I killed the program), which seems to about 1/3 of all eth nodes.
This seems like a lot to me and in a real scenario would probably only need a lot less connection.


### RLPx:
The RLPx part of the protocol is also done. The node can now securely connect to any ethereum node and send data frames.
I just have some code refactoring to do as it got quite messy - I am not a cryptography expert.

### Eth/Wire:
TODO

### Questions:
If a technical eth person stumbles across this, I have some questions / concerns:

1) Why am I able to discover and connect to so many nodes, isn't this a design flaw? I would imagine a bad actor would be able to connect to a lot of nodes this way and harm the network no?

2) It doesn't look like nodes have a good protection against one actor (IP) posing as several nodes (node ID / public key). With ~little modification, this one node instance could have several IDs and would hence be able to connect to even more nodes (as discovery connects you with nodes "close" to you).


## Roadmap:
 - [WIP] discv4 | for finding nodes [ref](https://github.com/ethereum/devp2p/blob/master/discv4.md)
 - [WIP] enr | store for node info [ref](https://github.com/ethereum/devp2p/blob/master/enr.md)
 - [WIP] rlpx | communicate with nodes [ref](https://github.com/ethereum/devp2p/blob/master/rlpx.md)
 - [TODO] wire | get block data from nodes [ref](https://github.com/ethereum/devp2p/blob/master/caps/eth.md)
 - [TODO] database | find the best database / way of storing block data in order to be able to query it super fast

## TODO:
  - general:
  - discv4:
    - respond to FindNode messages
    - respond to ENRRequest messages
  - rlpx:
    - refactor


## Credits:
 - go_ethereum rlp implementation
