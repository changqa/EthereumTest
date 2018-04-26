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
from packets import EndPoint, PingPacket, PongPacket

# Structure:
# Hash || Signature || packet_type || packet_data
# 32 Byte || 64 Byte + 1 Byte (for recoverable)|| 1 Byte || rest, rlp-encoded
# ptype ping = x01
# ptype pong = x02

# from geth source code:
# Endpoint of pong packet should reflect UDP envelope address of the ping packet

class PingServer(object):
    def __init__(self, my_endpoint, remote_endpoint, pingSleep, privKeyFile, kid):
        self.endpoint = my_endpoint
        print(str(self.endpoint))
        self.remote_endpoint = remote_endpoint
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
        self.sock.bind((self.endpoint.address.exploded, self.endpoint.udpPort))


    def startPingLoop(self):
        self.pingLoopThread = threading.Thread(target=self._pingLoop).start()

    def startListening(self):
        print("Server " + str(self.kid) + ", start listening")
        self.listenThread = threading.Thread(target=self._listenLoop).start()

    def _pingLoop(self):
        print("pingLoop")
        while True:
            self.ping(self.remote_endpoint)
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
            data, addr = self.sock.recvfrom(1024)
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
            print(pub.serialize().hex())

        if bytes([ptype]) == PingPacket.packet_type:
            print("Got ping.")
            recv_ping = PingPacket.unpack(rlp.decode(pdata))
            print(str(recv_ping))
            # self.pong(msg_hash, recv_ping.To())
            # TODO: Find out the correct endpoint
            self.pong(self.remote_endpoint, msg_hash)
        if bytes([ptype]) == PongPacket.packet_type:
            print("Got pong.")
            recv_pong = PongPacket.unpack(decdata)
            print(str(recv_pong))
            self.ping(recv_pong.From())


    def ping(self, endpoint):
        ping = PingPacket(self.endpoint, endpoint, time.time() + 60)
        message = self.wrap_packet(ping)
        print("sending ping.")
        self.sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))

    def pong(self, endpoint, echo):
        pong = PongPacket(endpoint, echo, time.time() + 60)
        message = self.wrap_packet(pong)
        print("sending pong.")
        self.sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))


class EchoServer(DatagramServer):

    def handle(self, data, address): # pylint:disable=method-hidden
        print('%s: got %r' % (address[0], data))
        self.socket.sendto(('Received %s bytes' % len(data)).encode('utf-8'), address)