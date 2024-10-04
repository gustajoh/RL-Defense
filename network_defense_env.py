from network_interactions import *  # Import your functions
import gym
from gym import spaces
import numpy as np
from constants import *


class NetworkDefenseEnv(gym.Env):
    def __init__(self):
        # 3 categories (detection, mitigation, containment)
        types = 3
        commands = 8
        nodes = 5
        users = 3
        snort_rules = 3
        firewall_rules = 6

        # [Category, Specific Action in that category]
        self.action_space = spaces.MultiDiscrete(
            [types, commands, nodes, users, snort_rules, firewall_rules])

    def step(self, action):
        response_type = action[0]
        specific_action = action[1]
        node = action[3]
        user = action[4]
        snort_rule = action[5]
        firewall_rule = action[6]

        # Detection
        if response_type == 0:
            if specific_action == 0:
                self.add_snort_rule(self, node, snort_rule)
            elif specific_action == 1:
                self.add_firewall_rule(self, node, firewall_rule)

        # Mitigation
        elif response_type == 1:
            if specific_action == 0:
                self.limit_traffic(node)

            elif specific_action == 1:
                self.blacklist_ip(node)

            elif specific_action == 2:
                self.limit_user(node, user)

        # Containment
        elif response_type == 2:
            if specific_action == 0:
                self.turn_off_node(node)

            elif specific_action == 1:
                self.isolate_node(node)

            elif specific_action == 2:
                self.migrate_node(node)

        observation = 'not implemented'
        reward = 'not implemented'
        done = 'not implemented'

        return observation, reward, done, {}
# Detection

    # Adds a random snort rule from constants.py and restarts snort to apply rule
    def add_snort_rule(self, node_id, index):
        rule = constants.SNORT_RULES[index]
        command = (
            f'echo "{rule}" >> /etc/snort/rules/local.rules '
            '&& snort -c /etc/snort/snort.conf -i eth0 eth1 eth2'
        )
        execute_command(node_id, command)
        print("SNORT rule added")

    # Adds shorewall rule from constants.py, restarts shorewall to apply
    def add_firewall_rule(self, node_id, index):
        rule = constants.SHOREWALL_RULES[index]
        command = (f'echo "{rule}" >> /etc/shorewall/rules '
                   '&& shorewall restart')
        execute_command(node_id, command)
        print("Firewall rule added")

# Mitigation

    # Adds target IP to blacklist and restarts firewall to apply updated blacklist
    def blacklist_ip(self, node_id, target_ip):
        command = (
            f'echo {target_ip} >> /etc/shorewall/blacklist '
            '&& shorewall restart'
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
        stop_node(node_id)
        print(f"Node {node_id} turned off")

    # Configures new IP within the DMZ zone and updates routing
    def migrate_node(self, node_id, new_ip, gateway_ip):
        command = (
            f'ifconfig eth0 {new_ip} netmask 255.255.255.0 '
            f'&& route add default gw {gateway_ip}'
        )
        execute_command(node_id, command)

    # Disables inbound and outbound traffic
    def isolate_node(self, node_id):
        command = "ifconfig eth0 down"
        execute_command(node_id, command)
        print(f"Node {node_id} isolated (interface down)")


# Other (maybe not usable here)

    def start_node(self, node_id):
        start_node(node_id)
        print(f"Node {node_id} restarted")

    def restart_node(self, node_id):
        restart_node(node_id)
        print(f"Node {node_id} restarted")
