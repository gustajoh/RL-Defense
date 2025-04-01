from environment_files.network_defense_env import *
from stable_baselines3.common.callbacks import CheckpointCallback
from sb3_contrib import RecurrentPPO


env = NetworkDefenseEnv()

model = RecurrentPPO("MultiInputLstmPolicy",
                     env,
                     n_steps=20,
                     batch_size=10,
                     verbose=1,
                     policy_kwargs={"lstm_hidden_size": 256}
                     )

checkpoint_callback = CheckpointCallback(
    save_freq=500,
    save_path="./model_checkpoints/",
    name_prefix="lstm_rppo_checkpoint"
)

try:
    model.learn(total_timesteps=5000, progress_bar=True, callback=checkpoint_callback)
except KeyboardInterrupt:
    print("Interrupted! Saving..")
    model.save("Emergency_checkpoint")
except Exception as e:
    print(f"Unexpected error: {e} Saving model")
    model.save("Unknown_checkpoint")

model.save("/models/RPPO_Model")