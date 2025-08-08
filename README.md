## Reinforcement Learning Framework for Autonomous Cyber Defense
Welcome to my thesis project!

The framework consists of two parts, a simulated network topology based on the lateral movement scenario from [AIT AttackBed project](https://github.com/ait-testbed/attackbed), and an implementation for a RL-environment integrating the network topology and modeling an APT-style attacker.

### Network Topology
The network topology is simulated using [Graphical Network Simulator-3](https://www.gns3.com/), requiring [VirtualBox](https://www.virtualbox.org/wiki/Downloads) and [Docker](https://www.docker.com/).
<p align="center">
<img style="width:70%;" alt="largetopology" src="https://github.com/user-attachments/assets/16fe74ef-49f7-496f-9b5b-19f74a0b475a" />
</p>

The topology can be imported with the included .gns3 file.
It is suggested to run GNS3 in the web gui. 
Included Dockerfiles should be placed and built **on the GNS3 VM**.
