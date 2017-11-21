import os, random as r
import metasploit

AGENTS = open(os.path.join(metasploit.DATA_DIR, 'user_agents.txt')).read().splitlines()

def random():
    r.choice(AGENTS)

def most_common():
    AGENTS[0]
