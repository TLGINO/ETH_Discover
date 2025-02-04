# ETH Discover

## Idea:

Will try and see if it is feasible to "download" the blockchain directly from nodes, without running execution + consensus client, but instead by being a passive gossiper.

## So far:
Discovery works pretty well and I am recursively connecting to nodes and requesting eth peers (IPs / ports) to connect to - hence building a map of ethereum.
I'm surprised that I'm able to connect to so many nodes (~2k before I killed the program) as (my understanding is) only nodes "close" to my ID are supposed to respond hence that number should be small??

## Roadmap:
 - [WIP] discv4 | for finding nodes [ref](https://github.com/ethereum/devp2p/blob/master/discv4.md)
 - [WIP] enr | store for node info [ref](https://github.com/ethereum/devp2p/blob/master/enr.md)
 - [WIP] rlpx | communicate with nodes [ref](https://github.com/ethereum/devp2p/blob/master/rlpx.md)
 - [TODO] wire | get block data from nodes [ref](https://github.com/ethereum/devp2p/blob/master/caps/eth.md)

## TODO:
  - general:
    - better logger
  - discv4:
    - respond to FindNode messages
    - respond to ENRRequest messages
  - rlpx:
    - do frames


## Credits:
 - go_ethereum rlp implementation
