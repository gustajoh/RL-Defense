from constants import *
import numpy as np
from network_attack_env import *
from network_defense_env import *
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.callbacks import CheckpointCallback


def_env = NetworkDefenseEnv()
#check_env(def_env)

model = PPO("MultiInputPolicy", def_env, verbose=1, n_steps=50, batch_size=10)
checkpoint_callback = CheckpointCallback(
    save_freq=500,
    save_path="./model_checkpoints/",
    name_prefix="ppo_checkpoint"
)

try:
    model.learn(total_timesteps=3000, progress_bar=True, callback=checkpoint_callback)
except KeyboardInterrupt:
    print("Interrupted! Saving..")
    model.save("Emergency_checkpoint")
except Exception as e:
    print(f"Unexpected error: {e} Saving model")
    model.save("Unknown_checkpoint")

model.save("PPO_300")