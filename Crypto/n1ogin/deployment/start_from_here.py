import os

port = 7777
command = 'socat -d -d tcp-l:' + str(port) + ',reuseaddr,fork EXEC:"python3 -u server.py" '
os.system(command)