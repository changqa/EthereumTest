#!/usr/bin/env python

import socket
import threading
import time
import struct
import rlp
from crypto import keccak256
from secp256k1 import PrivateKey, PublicKey
from ipaddress import ip_address
from gevent.server import DatagramServer
from packets import EndPoint, PingPacket, PongPacket, FindNodePacket, NeighborsPacket, Node

# Structure:
# Hash || Signature || packet_type || packet_data
# 32 Byte || 64 Byte + 1 Byte (for recoverable)|| 1 Byte || rest, rlp-encoded
# ptype ping = x01
# ptype pong = x02

# from geth source code:
# Endpoint of pong packet should reflect UDP envelope address of the ping packet

class PingServer(object):
    def __init__(self, my_endpoint, remote_endpoint, pingSleep, privKeyFile, kid):
        self.myEndpoint = my_endpoint
        self.theirEndpoint = remote_endpoint
        self.pingSleep = pingSleep
        self.kid = kid

        ## get private key
        pkf = open(privKeyFile, "r")
        priv_key_serialized = pkf.read()
        pkf.close()
        self.priv_key = PrivateKey()
        self.priv_key.deserialize(priv_key_serialized)

        ## init socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.myEndpoint.address.exploded, self.myEndpoint.udpPort))


    def startPingLoop(self):
        self.pingLoopThread = threading.Thread(target=self._pingLoop).start()

    def startListening(self):
        print("Server " + str(self.kid) + ", start listening")
        self.listenThread = threading.Thread(target=self._listenLoop).start()

    def _pingLoop(self):
        print("pingLoop")
        while True:
            self.ping(self.theirEndpoint)
            self.findnode(self.theirEndpoint, 0x6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0)
            # self.neighbors(self.theirEndpoint, 0x6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0)
            time.sleep(self.pingSleep)


    def wrap_packet(self, packet):
        payload = packet.packet_type + rlp.encode(packet.pack())
        sig = self.priv_key.ecdsa_sign_recoverable(keccak256(payload), raw = True)
        sig_serialized = self.priv_key.ecdsa_recoverable_serialize(sig)
        # print(str(type(sig_serialized[0])) + " " + str(type(sig_serialized[1])) + str(type(payload)))
        # print(sig_serialized[1])
        payload = sig_serialized[0] + bytes([sig_serialized[1]]) + payload

        payload_hash = keccak256(payload)
        return payload_hash + payload

    def _listenLoop(self):
        print("Start Listening...")
        while True:
            data, addr = self.sock.recvfrom(2048)
            print("--------------- New Packet (ID: " + str(self.kid) + ") -------------")
            self.handlePacket(data, addr)

    def handlePacket(self, data, addr):
        # print("received message[" +  str(addr) + "]")
        msg_hash = data[:32]    # 32 Byte Hash
        raw_sig = data[32:97]   # 64 Byte + 1 Byte Signature
        ptype = data[97]        # 1 Byte packet_type
        pdata = data[98:]       # Rest is rlp-encoded data
        decdata = rlp.decode(pdata)
        signedData = data[97:]
        
        # Verify hash
        if msg_hash != keccak256(data[32:]):
            print("Invalid message hash!")
            exit(0)

        # Verify signature
        deserialized_sig = self.priv_key.ecdsa_recoverable_deserialize(raw_sig[:64],
                                                           raw_sig[64])
        remote_pubkey = self.priv_key.ecdsa_recover(keccak256(signedData),
                                        deserialized_sig,
                                        raw = True)
        pub = PublicKey()
        pub.public_key = remote_pubkey
        verified = pub.ecdsa_verify(keccak256(signedData),
                        pub.ecdsa_recoverable_convert(deserialized_sig),
                        raw = True)

        if not verified:
            print("Signature invalid!")
            exit(0)
        else:
            print("Public Key: " + pub.serialize().hex())

        packet_type = bytes([ptype])
        if packet_type == PingPacket.packet_type:
            print("Got ping.")
            recv_ping = PingPacket.unpack(rlp.decode(pdata))
            print(str(recv_ping))
            # self.pong(msg_hash, recv_ping.To())
            # TODO: Find out the correct endpoint
            self.pong(self.theirEndpoint, msg_hash)
        
        if packet_type == PongPacket.packet_type:
            print("Got pong.")
            recv_pong = PongPacket.unpack(decdata)
            print(str(recv_pong))
            # self.ping(self.theirEndpoint)
        
        if packet_type == FindNodePacket.packet_type:
            print("Got FindNodePacket.")
            recv_findnode = FindNodePacket.unpack(rlp.decode(pdata))
            target = recv_findnode.target
            print("Target: " + str(target.hex()))
            self.neighbors(self.theirEndpoint, target)
        
        if packet_type == NeighborsPacket.packet_type:
            print("Got NeighborsPacket.")
            recv_neighbors = NeighborsPacket.unpack(rlp.decode(pdata))
            print("# Neighbors: " + str(len(recv_neighbors.neighbors)))


    def ping(self, theirEndpoint):
        ping = PingPacket(self.myEndpoint, theirEndpoint, time.time() + 60)
        message = self.wrap_packet(ping)
        print("Sending ping to: " + str(theirEndpoint))
        self.sock.sendto(message, (theirEndpoint.address.exploded, theirEndpoint.udpPort))

    def pong(self, theirEndpoint, echo):
        pong = PongPacket(theirEndpoint, echo, time.time() + 60)
        message = self.wrap_packet(pong)
        print("Sending pong to: " + str(theirEndpoint))
        self.sock.sendto(message, (theirEndpoint.address.exploded, theirEndpoint.udpPort))

    def findnode(self, theirEndpoint, target):
        findnode = FindNodePacket(target, time.time() + 60)
        message = self.wrap_packet(findnode)
        print("Sending FindNodePacket to: " + str(theirEndpoint))
        self.sock.sendto(message, (theirEndpoint.address.exploded, theirEndpoint.udpPort))

    def neighbors(self, theirEndpoint, target):
        # Compute some close neighbors on the fly
        neighbors = self.computeClosestNeighbors(target)
        packet = NeighborsPacket(neighbors, time.time() + 60)
        message = self.wrap_packet(packet)
        print("Sending NeighborsPacket to: " + str(theirEndpoint))
        self.sock.sendto(message, (theirEndpoint.address.exploded, theirEndpoint.udpPort))

    def computeClosestNeighbors(self, target):
        # Just return some hard coded IDs for now
        return [
            Node(self.myEndpoint.address, self.myEndpoint.udpPort, self.myEndpoint.tcpPort, 0x6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0),
            Node(self.myEndpoint.address, self.myEndpoint.udpPort, self.myEndpoint.tcpPort, 0x7f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0),
        ]
