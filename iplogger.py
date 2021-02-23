from scapy.all import *
import time
import socket
import requests
import json
import platform
import subprocess
import ipaddress
import colorama


#PeerBlock IP format
#Name:35.187.241.213-35.187.241.213
#Lobby UDP IP add ignore ip numbers - 35.204.94.124



# Use this option if you want Geo Loction on the IP address get your free api key from https://ipstack.com
# their databases arent so up to date but its a nice feature if you want to enable it


colorama.init()

# Ping the server 1 time to get the response time from the server

def ping(command):
	if ipaddress.ip_address(dest_ip).is_private == True:
		return
	else:
		process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
		proc_stdout = process.communicate()[0].strip()
		response_mstime = re.findall(r'time=(\d+)\w', proc_stdout.decode())
	try:
		response_time = int(response_mstime.pop())
	except IndexError:
		print('ICMP Ping Blocked by firewall, Is the Server IP already added to block list?')
		return

	return response_time



# getting our local IP address
def get_ip():
	# get the local machines IP address
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		# doesn't even have to be reachable
		s.connect(('10.255.255.255', 1))
		IP = s.getsockname()[0]
	except:
		IP = '127.0.0.1'
	finally:
		s.close()
	return IP

global local_ip
local_ip = get_ip()

def pc(packet):
	if packet.proto == 17:
		udp = packet.payload

# Clear the console on the next updated IP address for a cleaner console output
def clear():
    print ("\x1b[2J")



def function_1():
	# looking for UDP packets sent to port 37005 Apex Legends servers 
	x = sniff(filter="udp and portrange 37005-38515", prn=pc, store=1, count=1) # Do not capture local IP UDP it captures local UDP packets
	y = x[0][IP].src
	z = x[0][IP].dst
	global dest_ip
	if local_ip in y:
		dest_ip = z
	else:
		dest_ip = y

	if ipaddress.ip_address(dest_ip).is_private == True:
		return
	else:
		clear()
		response_time = ping('ping -n 1 {} | FIND "TTL="'.format(dest_ip)) # pings the server
		if response_time == None:
			return
		else:
			print('Game Server IP: {} Response time: {}ms'.format(dest_ip,response_time), sep=' ', end='\n', flush=True)
		if response_time is None:
			return
		elif response_time < 200:
			with open('Good-ApexServer.txt', 'a+') as the_file:
				the_file.seek(0)
				for line in the_file:
					if dest_ip in line: # wrong find better way to not add dupes
						print('[+]dest_ip already in file')
						break
					else:
						the_file.write(dest_ip + '\n')
		else:
			with open('ApexBadIP.p2p', 'a+') as the_file:
				the_file.seek(0)
				for line in the_file:
					if dest_ip in line: # wrong find better way to not add dupes
						print('[-]dest_ip already in file')
						break
					else:
						peerblock = 'Block:' + dest_ip + '-' + dest_ip + '\n' # Peerblock firewall config
						the_file.write(peerblock)
	return dest_ip


ip_flag = '0.0.0.0'
global response_time
response_time = '0'

# This is the main function
while True:
	function_1()
	input('Press Enter when your in a match')
