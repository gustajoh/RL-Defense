from network_defense_env import *
from stable_baselines3.common.env_checker import check_env


env = NetworkDefenseEnv()

check_env(env)