# Metasploit-Based Automated Penetration Testing using Reinforcement Learning

## 🔒 Overview
This project is a research-backed prototype that integrates **Nmap**, **Metasploit**, and **Reinforcement Learning (PPO)** to automate penetration testing.  
The tool scans a target system, maps discovered services to available exploits, and then uses a PPO agent to dynamically select and execute the most promising exploit–payload combinations.

Developed as part of an academic research paper, the framework demonstrates how reinforcement learning can accelerate and optimize vulnerability exploitation in real-world penetration testing.

## ⚙️ Features
- Automated **Reconnaissance**:
  - Nmap XML parsing to identify open ports, services, versions, and OS.
  - Mapping results to Metasploit’s exploit database.
- **Exploit Selection**:
  - Metasploit RPC integration to identify and execute compatible exploits.
  - PPO reinforcement learning agent for optimal exploit–payload decisions.
- **Reward-based Training**:
  - Rewards for successful sessions, privilege escalation, and exploration.
  - Negative rewards for failed exploits or redundant attempts.
- Continual learning with environment modification to simulate real-world changes.

## 📂 Project Structure
├── cmodel2.py # PPO environment and RL agent

├── parse3.py # Nmap parsing + Metasploit exploit mapping

├── requirements.txt # Python dependencies

├── README.md # Project documentation

├── docs/

│ └── Research_Paper.pdf # Full research paper

├── samples/

│ ├── nmap_scan.xml # Example Nmap scan

│ └── nmap_metasploit_results.json # Sample parsed output

## 🚀 Getting Started

### Prerequisites
- Linux environment
- Python 3.8+
- Metasploit installed and running
- Metasploit RPC server enabled (`msfrpcd`)
- `virtualenv` recommended

### Installation
```bash
git clone https://github.com/yourusername/automated-penetration-testing-rl.git
cd automated-penetration-testing-rl
pip install -r requirements.txt
```
Usage
Run an Nmap scan and export to XML:
```bash 
sudo nmap -sV -O <target-ip> -oX nmap_scan.xml
```

Parse scan results and map exploits:
```bash
python3 parse3.py
```

Output will be saved as nmap_metasploit_results.json.

Run PPO-based exploitation:
```bash 
python3 cmodel2.py
```

## 🧠 Research Background

This project was also presented in the paper:

[“Metasploit-Based Automated Penetration Testing Using Reinforcement Learning”](https://ieeexplore.ieee.org/document/10863399)

It introduces PPO as a reinforcement learning algorithm for real-time exploit selection, addressing the shortcomings of traditional manual penetration testing.


## 🔮 Future Work
Expand beyond Metasploit’s built-in modules with Exploit-DB integration.

Add attack graph visualization via MulVAL.

Support multi-stage exploitation and lateral movement.
