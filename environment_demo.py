from constants import *
import numpy as np
from network_attack_env import *
from network_defense_env import *
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env

def_env = NetworkDefenseEnv()
#check_env(def_env)

model = PPO("MultiInputPolicy", def_env, verbose=1, n_steps=50)
model.learn(total_timesteps=50, progress_bar=True)
# atk_env = NetworkAttackEnv()
# # check_env(def_env)
# atk_action = [[0,0,0], [1,0,0], [0,2,0] ,[0,0,0], [1,0,2]]
# def_action = [[3,0,0,0,0], [2,0,2,1,2], [0,0,1,0,2], [2,1,1,0,1], [3,1,2,0,1]]

# atk_episode = []
# def_episode = []

# atk_reward = 0
# for i in range(10):
#     if(i%2 == 0):
#         print("Attacker")
#         obs, reward, terminated, truncated, info = atk_env.step(atk_action[i//2])
#         atk_reward = reward
#         atk_episode.append((obs, reward, terminated))
#         print()
#     else:
#         print("Defender")
#         obs, reward, terminated, truncated, info = def_env.step(def_action[i//2], atk_reward)
#         def_episode.append((obs, reward, terminated))
#         print()


# print("Attacker result")
# for step in atk_episode:
#     print(step)
# print()
# print("Defender result")
# for step in def_episode:
#     print(step)

# with open("attacker_results.txt", "w") as atk_out, open("defender_results.txt", "w") as def_out:
#     # Write attacker results
#     atk_out.write("Attacker result:\n")
#     for step in atk_episode:
#         atk_out.write(f"{step}\n")

#     # Write defender results
#     def_out.write("Defender result:\n")
#     for step in def_episode:
#         def_out.write(f"{step}\n")




