from network_interactions import *  # Import your functions
import gym
from gym import spaces
import numpy as np
from constants import *
import re
import xml.etree.ElementTree as ET

class NetworkAttackEnv(gym.Env):
    def __init__(self):
        types = 3
        commands = 8
        intensity = 5
        self.observation_space = spaces.Dict({
            "known_credentials": spaces.MultiBinary(4),
            "compromised_nodes": spaces.MultiBinary(10),  
            "found_hosts": spaces.MultiBinary(4),
            "available_tools": spaces.MultiBinary(5)
        })

        self.action_space = spaces.MultiDiscrete([types, commands, intensity])
        
    def step(self, action):
        response_type = action[0]
        specific_action = action[1]
        subnet = ''
        intensity = ''
        ip = ''

        # Exploraiton
        if response_type == 0:
            if specific_action == 0:
                self.scan_range(self, subnet, intensity)
            elif specific_action == 1:
                self.traffic_scan(self)
            elif specific_action == 2:
                self.connect_to_host(self, ip)

        # Exploitation
        elif response_type == 1:
            if specific_action == 0:
                self.brute_force(self, ip)

        # Obfuscation
        elif response_type == 2:
            'none'

        observation = { }
        reward = 'not implemented'
        done = 'not implemented'

        return observation, reward, done, {}
    
# Exploration
    def scan_range(self, subnet, intensity):
        command = constants.NMAP_SCANS[intensity] + f' ${subnet}-10'
        print(f"Port scanning with intensity ${intensity}")
        result = interact(command)
        return result

    def traffic_scan(self):
        command = "tcpdump -i any -c 100"
        result = interact(command)
        return result
    
    def connect_to_host(self, host):
        command = f"ssh {self.known_credentials[host]['user']}@{host}"
        result = interact(command)

# Exploitation
    def brute_force(self, target):
        command = f'medusa -h {target} -U /usr.txt -P /pass.txt -M ssh | grep FOUND'
        result = interact(command)
        return result

   
# Obfuscation
   
# Other (maybe not usable here)

    def start_node(self, node_id):
        start_node(node_id)
        print(f"Node {node_id} restarted")

    def restart_node(self, node_id):
        restart_node(node_id)
        print(f"Node {node_id} restarted")

# Observation methods

# Helper methods
def parse_scan_output(data):
    root = ET.fromstring(data)
    hosts = []
    
    for host in root.findall("host"):
        status = host.find("status").get("state")
        if status == "up":
            ip = host.find("address").get("addr")
            state = host.find("status").get("state")
            hosts.append({"ip": ip, "state": state})
    return hosts

def parse_medusa_output(output):
    pattern = r"ACCOUNT FOUND: \[ssh\] Host: (\S+) User: (\S+) Password: (\S+) \[SUCCESS\]"
    credentials = {}

    for line in output.splitlines():
        match = re.search(pattern, line)
        if match:
            host, user, password = match.groups()
            credentials[host] = {"user": user, "password": password}
    
    return credentials

def interact(command):
    result = execute_command(constants.DOCKER_NODES['COZYBEAR'], command)
    return result