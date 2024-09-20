from network_interactions import *  # Import your functions
import gym
from gym import spaces
import numpy as np

class NetworkDefenseEnv(gym.Env):
    def __init__(self):
        # 3 categories (detection, mitigation, containment)
        types = 3
        commands = 8
        nodes = 5
        users = 3



        self.action_space = spaces.MultiDiscrete([types, commands, nodes, users])  # [Category, Specific Action in that category]

    def step(self, action):
        response_type = action[0]
        specific_action = action[1]
        node = action[3]
        user = action[4]
        
        # Detection
        if response_type == 0:  
            if specific_action == 0:
                self.add_snort_rule()
            elif specific_action == 1:
                self.add_firewall_rule()
        
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
    def add_snort_rule(self, node_id):
        command = 'not implemented'
        execute_command(node_id, command)
    
    def add_firewall_rule(self, node_id):
        command = 'not implemented'
        execute_command(node_id, command)

# Mitigation
    def blacklist_ip(self, node_id):
        command = 'not implemented'
        execute_command(node_id, command)
    
    def limit_user(self, node_id, user):
        command = 'not implemented, make case for each user'
        execute_command(node_id, command)
    
    def limit_traffic(self, node_id):
        command = 'not implemented'
        execute_command(node_id, command)

# Containment
    def turn_off_node(self, node_id):
        stop_node(node_id)
        print(f"Node {node_id} turned off")

    def migrate_node(self, node_id):
        command = 'not implemented'
        execute_command(node_id, command)

    def isolate_node(self, node_id):
        command = "ifconfig eth0 down"
        execute_command(node_id, command)
        print(f"Node {node_id} isolated (interface down)")

# other (maybe not usable here)
    def start_node(self, node_id):
        start_node(node_id)
        print(f"Node {node_id} restarted")

    def restart_node(self, node_id):
        restart_node(node_id)
        print(f"Node {node_id} restarted")


