# Revagg 


Usage:

# Reverse-IP on an IP

python3 revagg.py 93.184.216.34

# Or start from a domain (script will resolve IP and also query certificate transparency)

python3 revagg.py example.com

# default ports (80,443,8080,8443) with 20 workers

python3 revagg.py example.com

# custom ports and workers

python3 revagg.py 93.184.216.34 --ports 80,443 --workers 40 --timeout 6
