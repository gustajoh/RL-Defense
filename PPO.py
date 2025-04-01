from network_defense_env import *
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import CheckpointCallback


env = NetworkDefenseEnv()

model = PPO("MultiInputPolicy", env, verbose=1, n_steps=20, batch_size=10)

checkpoint_callback = CheckpointCallback(
    save_freq=500,
    save_path="./model_checkpoints/",
    name_prefix="ppo_checkpoint"
)

try:
    model.learn(total_timesteps=5000, progress_bar=True, callback=checkpoint_callback)
except KeyboardInterrupt:
    print("Interrupted! Saving..")
    model.save("Emergency_checkpoint")
except Exception as e:
    print(f"Unexpected error: {e} Saving model")
    model.save("Unknown_checkpoint")

model.save("PPO_v2")