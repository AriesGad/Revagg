# Revagg 

revagg.py - Reverse-IP / hostname aggregator + colored HTTP probe (Termux-friendly, no-root)

Installation:

git clone https://github.com/AriesGad/Revagg.git

cd revagg

Usage:

# Reverse-IP on an IP

python3 revagg.py 93.184.216.34

# Or start from a domain (script will resolve IP and also query certificate transparency)

python3 revagg.py example.com

# default ports (80,443,8080,8443) with 20 workers

python3 revagg.py example.com

# custom ports and workers

python3 revagg.py 93.184.216.34 --ports 80,443 --workers 40 --timeout 6

Outputs:
  revagg_candidates.txt  - deduped hostnames
  revagg_live.txt        - CSV of live hits (Method,Code,Server,Port,IP,Host)
  revagg_debug.log       - debug / source details

Notes:
 - Uses PTR, hackertarget, viewdns.info, crt.sh (when domain given).
 - Built-in HTTP probe checks ports you pass (default: 80,443,8080,8443).
 - Colored table output (requires colorama).
 - Only test targets you own or have explicit permission to test.
"""
