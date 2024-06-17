import tensorflow as tf
from tensorflow.keras.layers import Input, Dense, LSTM, Concatenate, ReLU
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
import numpy as np
import random
from collections import deque

# Define the neural network architecture
def create_network(state_size, action_size, time_series_size):
    # Feature extraction module for static features
    static_input = Input(shape=(state_size,))
    x = Dense(128, activation='relu')(static_input)
    x = Dense(64, activation='relu')(x)

    # Time-series analysis module for dynamic features
    time_series_input = Input(shape=(time_series_size, 1))
    y = LSTM(64, activation='relu')(time_series_input)
    y = Dense(32, activation='relu')(y)

    # Feature fusion module
    z = Concatenate()([x, y])
    z = Dense(64, activation='relu')(z)

    # Q-Network output layer
    output = Dense(action_size)(z)

    model = Model(inputs=[static_input, time_series_input], outputs=output)
    model.compile(loss='mse', optimizer=Adam(lr=0.001))
    return model

# Define a function to update the target network
def update_target_model(target_network, main_network):
    target_network.set_weights(main_network.get_weights())

# Function to act based on model's output
def choose_action(state, time_series, main_network, action_size, epsilon):
    if np.random.rand() <= epsilon:
        return random.randrange(action_size)
    act_values = main_network.predict([state, time_series])
    return np.argmax(act_values[0])

# Learning function
def replay(memory, main_network, target_network, batch_size, gamma, epsilon, epsilon_min, epsilon_decay, train_start):
    if len(memory) < train_start:
        return
    minibatch = random.sample(memory, batch_size)
    for state, time_series, action, reward, next_state, next_time_series, done in minibatch:
        target = main_network.predict([state, time_series])
        if done:
            target[0][action] = reward
        else:
            t = target_network.predict([next_state, next_time_series])
            target[0][action] = reward + gamma * np.amax(t[0])
        main_network.fit([state, time_series], target, epochs=1, verbose=0)
    if epsilon > epsilon_min:
        epsilon *= epsilon_decay

def calculate_reward(current_state, current_time_series, next_state, next_time_series):
    reward = 0

    # Parameters to control the scale of reward and penalty
    hcr_weight = 100
    vulnerability_weight = 50
    mttc_weight = 20
    exposure_penalty = 100
    mtd_time_penalty = 50

    # Reward for reducing Host Compromise Ratio
    reward += (current_state[0] - next_state[0]) * hcr_weight

    # Reward for reducing the number of vulnerabilities
    reward += (current_state[1] - next_state[1]) * vulnerability_weight

    # Reward for increasing Mean Time to Compromise
    reward += (next_time_series[1] - next_time_series[1]) * mttc_weight

    # Penalty for increased Attack Path Exposure Score
    reward -= (next_state[2] - current_state[2]) * exposure_penalty

    # Penalty for high Time Since Last MTD
    if next_time_series[2] > current_time_series[2]:
        reward -= (next_time_series[2] - current_time_series[2]) * mtd_time_penalty

    return reward