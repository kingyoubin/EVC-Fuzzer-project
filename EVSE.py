"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

    This class is used to emulate an EVSE when talking to a PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

import sys
import os
import time
import argparse
import xml.etree.ElementTree as ET
import binascii
from threading import Thread, Event

# Add custom library paths
sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")

# Import custom layers and modules
from layers.SECC import *
from layers.V2G import *
from layerscapy.HomePlugGP import *
from XMLBuilder import XMLBuilder
from EXIProcessor import EXIProcessor
from EmulatorEnum import *
from NMAPScanner import NMAPScanner

# Import Scapy components
from scapy.all import (
    sendp,
    sniff,
    Ether,
    AsyncSniffer,
    Raw,
    IPv6,
    UDP,
    TCP,
    ICMPv6ND_NA,
    ICMPv6NDOptDstLLAddr,
    ICMPv6ND_NS,
)


class EVSE:
    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = args.interface[0] if args.interface else "eth1"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:1e:c0:f2:6c:a0"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::21e:c0ff:fef2:6ca0"
        self.sourcePort = args.source_port[0] if args.source_port else 25565
        self.NID = args.NID[0] if args.NID else b"\x9c\xb0\xb2\xbb\xf5\x6c\x0e"
        self.NMK = (
            args.NMK[0]
            if args.NMK
            else b"\x48\xfe\x56\x02\xdb\xac\xcd\xe5\x1e\xda\xdc\x3e\x08\x1a\x52\xd1"
        )
        self.protocol = Protocol(args.protocol[0]) if args.protocol else Protocol.DIN
        self.nmapMAC = args.nmap_mac[0] if args.nmap_mac else ""
        self.nmapIP = args.nmap_ip[0] if args.nmap_ip else ""
        self.nmapPorts = []
        if args.nmap_ports:
            for arg in args.nmap_ports[0].split(","):
                if "-" in arg:
                    i1, i2 = arg.split("-")
                    for i in range(int(i1), int(i2) + 1):
                        self.nmapPorts.append(i)
                else:
                    self.nmapPorts.append(int(arg))
        if args.modified_cordset:
            self.modified_cordset = True
        else:
            self.modified_cordset = False
        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None

        self.exi = EXIProcessor(self.protocol)

        self.slac = _SLACHandler(self)
        self.tcp = _TCPHandler(self)

        # I2C bus for relays
        # self.bus = SMBus(1)

        # Constants for i2c controlled relays
        self.I2C_ADDR = 0x20
        self.CONTROL_REG = 0x9
        self.EVSE_CP = 0b1
        self.EVSE_PP = 0b1000
        self.ALL_OFF = 0b0

    # Start the emulator
    def start(self):
        # Initialize the I2C bus for write
        # self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)

        self.toggleProximity()
        self.doSLAC()
        self.doTCP()
        # If NMAP is not done, restart connection
        if not self.tcp.finishedNMAP:
            print("INFO (EVSE): Attempting to restart connection...")
            self.start()

    # Close the circuit for the proximity pins
    def closeProximity(self):
        if self.modified_cordset:
            print("INFO (EVSE): Closing CP/PP relay connections")
            # self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_PP | self.EVSE_CP)
        else:
            print("INFO (EVSE): Closing CP relay connection")
            # self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_CP)

    # Close the circuit for the proximity pins
    def openProximity(self):
        print("INFO (EVSE): Opening CP/PP relay connections")
        # self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)

    # Opens and closes proximity circuit with a delay
    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()

    # Starts TCP/IPv6 thread that handles layer 3 comms
    def doTCP(self):
        self.tcp.start()
        print("INFO (EVSE): Done TCP")

    # Starts SLAC thread that handles layer 2 comms
    def doSLAC(self):
        self.slac.start()
        self.slac.sniffThread.join()
        print("INFO (EVSE): Done SLAC")


# Handles all SLAC communications
class _SLACHandler:
    def __init__(self, evse: EVSE):
        self.evse = evse
        self.iface = self.evse.iface
        self.sourceMAC = self.evse.sourceMAC
        self.sourceIP = self.evse.sourceIP
        self.sourcePort = self.evse.sourcePort
        self.NID = self.evse.NID
        self.NMK = self.evse.NMK

        self.timeout = 8
        self.stop = False
        self.exception_event = Event()  # Event to signal exception

    # Starts SLAC process
    def start(self):
        self.stop = False
        print("INFO (EVSE): Sending SET_KEY_REQ")
        sendp(self.buildSetKey(), iface=self.iface, verbose=0)
        self.sniffThread = Thread(target=self.startSniff)
        self.sniffThread.start()

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        # Wait for threads to finish or exception to occur
        while self.sniffThread.is_alive():
            if self.exception_event.is_set():
                print("INFO (EVSE): Exception occurred in SLACHandler, stopping...")
                self.stop = True
                break
            time.sleep(0.1)

    def checkForTimeout(self):
        self.lastMessageTime = time.time()
        while True:
            if self.stop:
                break
            if time.time() - self.lastMessageTime > self.timeout:
                print("INFO (EVSE): SLAC timed out, resetting connection...")
                self.evse.toggleProximity()
                self.lastMessageTime = time.time()
            time.sleep(0.5)

    def startSniff(self):
        try:
            sniff(iface=self.iface, prn=self.handlePacket, stop_filter=self.stopSniff)
        except Exception as e:
            print(f"Exception in SLACHandler sniff thread: {e}")
            self.exception_event.set()

    def stopSniff(self, pkt):
        if pkt.haslayer("SECC_RequestMessage"):
            print("INFO (EVSE): Received SECC_RequestMessage")
            # self.evse.destinationMAC = pkt[Ether].src
            # use this to send 3 secc responses in case car doesn't see one
            self.destinationIP = pkt[IPv6].src
            self.destinationPort = pkt[UDP].sport
            Thread(target=self.sendSECCResponse).start()
            self.stop = True
        return self.stop

    def sendSECCResponse(self):
        time.sleep(0.2)
        for i in range(3):
            print("INFO (EVSE): Sending SECC_ResponseMessage")
            sendp(self.buildSECCResponse(), iface=self.iface, verbose=0)

    def handlePacket(self, pkt):
        try:
            if pkt[Ether].type != 0x88E1 or pkt[Ether].src == self.sourceMAC:
                return

            self.lastMessageTime = time.time()

            if pkt.haslayer("CM_SLAC_PARM_REQ"):
                print("INFO (EVSE): Received SLAC_PARM_REQ")
                self.destinationMAC = pkt[Ether].src
                self.runID = pkt[CM_SLAC_PARM_REQ].RunID
                print("INFO (EVSE): Sending CM_SLAC_PARM_CNF")
                sendp(self.buildSlacParmCnf(), iface=self.iface, verbose=0)

            if pkt.haslayer("CM_MNBC_SOUND_IND") and pkt[CM_MNBC_SOUND_IND].Countdown == 0:
                print("INFO (EVSE): Received last MNBC_SOUND_IND")
                print("INFO (EVSE): Sending ATTEN_CHAR_IND")
                sendp(self.buildAttenCharInd(), iface=self.iface, verbose=0)

            if pkt.haslayer("CM_SLAC_MATCH_REQ"):
                print("INFO (EVSE): Received SLAC_MATCH_REQ")
                print("INFO (EVSE): Sending SLAC_MATCH_CNF")
                sendp(self.buildSlacMatchCnf(), iface=self.iface, verbose=0)
        except Exception as e:
            print(f"Exception in SLACHandler handlePacket: {e}")
            self.exception_event.set()

    # ... [Rest of the methods in _SLACHandler remain unchanged] ...


class _TCPHandler:
    def __init__(self, evse: EVSE):
        self.evse = evse
        self.iface = self.evse.iface

        self.sourceMAC = self.evse.sourceMAC
        self.sourceIP = self.evse.sourceIP
        self.sourcePort = self.evse.sourcePort

        self.destinationMAC = self.evse.destinationMAC
        self.destinationIP = self.evse.destinationIP
        self.destinationPort = self.evse.destinationPort

        self.seq = 10000
        self.ack = 0

        self.exi = self.evse.exi
        self.xml = XMLBuilder(self.exi)
        self.msgList = {}

        self.stop = False
        self.scanner = None

        self.timeout = 5
        self.finishedNMAP = True  # Added to prevent AttributeError
        self.exception_event = Event()  # Event to signal exception

    def start(self):
        self.msgList = {}
        self.running = True
        print("INFO (EVSE): Starting TCP")
        self.startSniff = False

        self.recvThread = Thread(target=self.recv)
        self.recvThread.start()

        while not self.startSniff:
            if self.exception_event.is_set():
                print("INFO (EVSE): Exception occurred in TCPHandler, stopping...")
                self.running = False
                return
            time.sleep(0.1)

        self.handshakeThread = Thread(target=self.handshakeSniff)
        self.handshakeThread.start()

        self.neighborSolicitationThread = Thread(target=self.neighborSolicitationSniff)
        self.neighborSolicitationThread.start()

        while self.running:
            if self.exception_event.is_set():
                print("INFO (EVSE): Exception occurred in TCPHandler, stopping...")
                self.killThreads()
                break
            time.sleep(1)

    def recv(self):
        try:
            self.recvSniffer = AsyncSniffer(
                iface=self.iface,
                lfilter=lambda x: x.haslayer("TCP")
                and x[TCP].sport == self.destinationPort
                and x[TCP].dport == self.sourcePort,
                prn=self.handlePacket,
                started_callback=self.setStartSniff,
            )
            self.recvSniffer.start()
            self.recvSniffer.join()
        except Exception as e:
            print(f"Exception in TCPHandler recv thread: {e}")
            self.exception_event.set()

    def handshakeSniff(self):
        try:
            self.handshakeSniffer = AsyncSniffer(
                count=1,
                iface=self.iface,
                lfilter=lambda x: x.haslayer("IPv6")
                and x.haslayer("TCP")
                and x[TCP].flags == "S",
                prn=self.handshake,
            )
            self.handshakeSniffer.start()
            self.handshakeSniffer.join()
        except Exception as e:
            print(f"Exception in TCPHandler handshake thread: {e}")
            self.exception_event.set()

    def neighborSolicitationSniff(self):
        try:
            self.neighborSolicitationSniffer = AsyncSniffer(
                iface=self.iface,
                lfilter=lambda x: x.haslayer("ICMPv6ND_NS")
                and x[ICMPv6ND_NS].tgt == self.sourceIP,
                prn=self.sendNeighborSolicitation,
            )
            self.neighborSolicitationSniffer.start()
            self.neighborSolicitationSniffer.join()
        except Exception as e:
            print(f"Exception in TCPHandler neighbor solicitation thread: {e}")
            self.exception_event.set()

    def handlePacket(self, pkt):
        try:
            self.last_recv = pkt
            self.seq = self.last_recv[TCP].ack
            self.ack = self.last_recv[TCP].seq + len(self.last_recv[TCP].payload)

            if "F" in self.last_recv[TCP].flags:
                self.fin()
                return
            if "P" not in self.last_recv[TCP].flags:
                return

            self.lastMessageTime = time.time()

            data = self.last_recv[Raw].load
            v2g = V2GTP(data)
            payload = v2g.Payload
            # Save responses to decrease load on java webserver
            if payload in self.msgList.keys():
                exi = self.msgList[payload]
            else:
                exi = self.getEXIFromPayload(payload)
                if exi is None:
                    return
                self.msgList[payload] = exi

            sendp(self.buildV2G(binascii.unhexlify(exi)), iface=self.iface, verbose=0)
        except Exception as e:
            print(f"Exception in TCPHandler handlePacket: {e}")
            self.exception_event.set()

    # ... [Rest of the methods in _TCPHandler remain unchanged] ...


if __name__ == "__main__":
    # Parse arguments from command line
    parser = argparse.ArgumentParser(description="EVSE emulator for AcCCS")
    parser.add_argument(
        "-M",
        "--mode",
        nargs=1,
        type=int,
        help="Mode for emulator to run in: 0 for full conversation, 1 for stalling the conversation, 2 for portscanning (default: 0)",
    )
    parser.add_argument(
        "-I",
        "--interface",
        nargs=1,
        help="Ethernet interface to send/receive packets on (default: eth1)",
    )
    parser.add_argument(
        "--source-mac",
        nargs=1,
        help="Source MAC address of packets (default: 00:1e:c0:f2:6c:a0)",
    )
    parser.add_argument(
        "--source-ip",
        nargs=1,
        help="Source IP address of packets (default: fe80::21e:c0ff:fef2:72f3)",
    )
    parser.add_argument(
        "--source-port",
        nargs=1,
        type=int,
        help="Source port of packets (default: 25565)",
    )
    parser.add_argument(
        "--NID",
        nargs=1,
        help="Network ID of the HomePlug GreenPHY AVLN (default: \\x9c\\xb0\\xb2\\xbb\\xf5\\x6c\\x0e)",
    )
    parser.add_argument(
        "--NMK",
        nargs=1,
        help="Network Membership Key of the HomePlug GreenPHY AVLN (default: \\x48\\xfe\\x56\\x02\\xdb\\xac\\xcd\\xe5\\x1e\\xda\\xdc\\x3e\\x08\\x1a\\x52\\xd1)",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        nargs=1,
        help="Protocol for EXI encoding/decoding: DIN, ISO-2, ISO-20 (default: DIN)",
    )
    parser.add_argument(
        "--nmap-mac",
        nargs=1,
        help="The MAC address of the target device to NMAP scan (default: EVCC MAC address)",
    )
    parser.add_argument(
        "--nmap-ip",
        nargs=1,
        help="The IP address of the target device to NMAP scan (default: EVCC IP address)",
    )
    parser.add_argument(
        "--nmap-ports",
        nargs=1,
        help="List of ports to scan separated by commas (ex. 1,2,5-10,19,...) (default: Top 8000 common ports)",
    )
    parser.add_argument(
        "--modified-cordset",
        action="store_true",
        help="Set this option when using a modified cordset during testing of a target vehicle. The AcCCS system will provide a 150 ohm ground on the proximity line to reset the connection. (default: False)",
    )
    args = parser.parse_args()

    while True:
        try:
            evse = EVSE(args)
            evse.start()
        except KeyboardInterrupt:
            print("INFO (EVSE): Shutting down emulator")
            evse.openProximity()
            del evse
            break
        except Exception as e:
            print("An error occurred:", e)
            print("Restarting EVSE...")
            evse.openProximity()
            del evse
            time.sleep(1)  # wait a bit before restarting
            continue
