import os
import subprocess

# Run Rasa actions server
actions_process = subprocess.Popen(['rasa', 'run', 'actions'])

# Run Rasa server
os.system('rasa run --enable-api')
