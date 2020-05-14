#! /usr/bin/env python3

import argparse
import socket
import sys
import ssl
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

class ConnManager:
    def connect(self):
        self.close() # clean up
        if (self.protocol == "TCP"):
            socket_type = socket.SOCK_STREAM
        elif (self.protocol == "UDP"):
            socket_type = socket.SOCK_DGRAM
        self.sock = socket.socket(socket.AF_INET, socket_type)
        self.sock.settimeout(self.SOCKET_TIMEOUT)
        try:
            if (self.ssl == True) and self.protocol == "TCP":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.sock = context.wrap_socket(self.sock, server_hostname=self.ipaddr)
            self.sock.connect((self.ipaddr, self.port))
            return True
        except Exception as e:
            if self.debug == True:
                print("connect Exception: " + str(e))
            self.sock.close()
            self.sock = None
            return False

    def getresponse(self, data, length = 1, binary = False):
        try:
            if binary == False:
                data = data.encode()
            if (self.protocol == "TCP"):
                self.sock.sendall(data)
                return self.sock.recv(length)
            elif (self.protocol == "UDP"):
                self.sock.sendto(data, (self.ipaddr, self.port))
                return self.sock.recvfrom(length)[0]
        except Exception as e:
            if self.debug == True:
                print("getresponse Exception: " + str(e))
            return b""


    def close(self):
        if (self.sock != None):
            self.sock.close()
            self.sock = None

    def __init__(self, ipaddr, port, protocol = "TCP", ssl = False, debug = False):
        self.ipaddr = ipaddr
        self.port = port
        self.protocol = protocol
        self.ssl = ssl
        self.debug = debug
        self.sock = None
        self.SOCKET_TIMEOUT = 3

class Inou:
    """ I Know You, main class """

    def isHTTP(self, cm):
        data = "GET /index.html HTTP/1.1\r\nHost: " + cm.ipaddr + "\r\n\r\n"
        return cm.protocol == "TCP" and cm.connect() and (cm.getresponse(data, 4).decode() == "HTTP")

    def isRTSP(self, cm):
        data = "OPTIONS rtsp://" + cm.ipaddr + ":" + str(cm.port) + "/stream?data_source_id=0 RTSP/1.0\r\nCSeq: 2\r\n\r\n"
        return cm.protocol == "TCP" and cm.connect() and (cm.getresponse(data, 4).decode() == b"RTSP")

    def isFTP(self, cm):
        data = "RETR test.txt\r\n\r\n"
        if cm.connect():
            response = cm.getresponse(data, 3).decode()
            return cm.protocol == "TCP" and cm.connect() and (response == "530" or response == "220")
        return False

    def isSMTP(self, cm):
        data = "HELO example\r\n\r\n"
        return cm.protocol == "TCP" and cm.connect() and (cm.getresponse(data).decode() == "2")

    def isSNMP(self, cm):
        # SNMP 'get-request' raw packet
        data = (b"\x30\x29\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1c\x02"
                b"\x04\x10\xbd\x19\x8c\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06"
                b"\x08\x2b\x06\x01\x02\x01\x01\x05\x00\x05\x00")
        return cm.protocol == "UDP" and cm.connect() and ("public" in cm.getresponse(data, 13, True).decode())

    def isZMQ(self, cm):
        data = b"\xff\x00\x00\x00\x00\x00\x00\x00\x01\x7f"
        return cm.protocol == "TCP" and cm.connect() and cm.getresponse(data,2, True) == b"\xff\x00"

    def isTELNET(self, cm):
        data = b"\xff\xfb\x01" # Will Echo request
        if cm.protocol == "TCP" and cm.connect():
            resp = cm.getresponse(data,2,True)
            return len(resp) > 2 and (resp[0] == 0xff) and (resp[1] > 0xf0)
        return False

    def isSSH(self, cm):
        data = "SSH-1.99-Cisco-1.25\n"
        if cm.connect():
            response = cm.getresponse(data, 3).decode()
            #GetResponse can return data of the application banner sent 
            return cm.protocol == "TCP" and (response == "SSH") or (len(response) > 0 and response[0] == "\x00")
        return False

    def isSIP(self, cm):
        data = ("INFO sip:alice@pc33.example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.2:5060;branch=z9hG4bKnabcdef\r\n"
                "To: Bob <sip:bob@example.com>;tag=a6c85cf\r\nFrom: Alice <sip:alice@example.com>;tag=1928301774\r\n"
                "Call-Id: a84b4c76e66710@pc33.example.com\r\nCSeq: 314333 INFO\r\n\r\n")
        return cm.protocol == "TCP" and cm.connect() and (cm.getresponse(data, 3).decode() == "SIP")

    def isJSON(self, cm):
        #Detect a custom server that uses json messages
        data = '{ "id" : 0, "user" : "bob", "password" : "a"}' #Some common keys
        return cm.connect() and (cm.getresponse(data).decode() == "{")

    def isXML(self, cm):
        #Detect a custom server that uses xml messages
        data = '<?xml version="1.0" encoding="UTF-8"?><java version="1.8.0_92" class="java.beans.XMLDecoder"><object class="com.test"><value>1</value><object></brokentag></object></java>' #Some common keys
        return cm.connect() and (cm.getresponse(data).decode() == "<")

    def isBINARY(self, cm):
        #Detect a custom server that uses unknown binary messages
        data = b'\x0e\x01\x7f\x41\x41\x42\x80\x45\x90\xab\x00\r\n\r\n' #Some random bytes (except the first that is the len)
        return cm.connect() and (len(cm.getresponse(data, 1, True)) > 0)
    
    def detectService(self):
        result = ""
        futures = []
        executor = ThreadPoolExecutor(multiprocessing.cpu_count())
        cm = ConnManager(self.ipaddr, self.port, self.protocol, self.ssl, self.debug)
        # Use reflection to run all the methods named isPROTOCOL
        for func in dir(self):
            if func.startswith('is') and (func != "isBINARY"):
                if self.parallel == True:
                    cm = ConnManager(self.ipaddr, self.port, self.protocol, self.ssl, self.debug)
                    futures += [(executor.submit(getattr(self, func), (cm)), func[2:])]
                else:
                    try:
                        if getattr(self, func)(cm): # Service found
                            result = func[2:]
                            break
                    except Exception as e:
                        if self.debug == True:
                            print ("detectService Exception: " + e.message)
                        pass
        
        for (future, func) in futures:
            if future.result() == True:
                result = func
                break

        # Make the last attempt with the most coarse test
        if result == "" and self.isBINARY(cm):
            result = "BINARY"

        if (self.ssl == True) and result != "":
            result = result + "/SSL"
        return result


    def __init__(self, ipaddr, port, protocol = "TCP", ssl = False, parallel = False, debug = False):
        self.ipaddr = ipaddr
        self.port = port
        self.protocol = protocol
        self.ssl = ssl
        self.parallel = parallel
        self.debug = debug


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip_address", help="Target ip address where the service is installed", type=str)
    parser.add_argument("port", help="Target port address where the service is listening", type=int)
    parser.add_argument("-u", "--udp", help="Use UDP instead of TCP", action="store_true")
    parser.add_argument("-s", "--ssl", help="Use SSL sockets (default: False)", action="store_true")
    parser.add_argument("-p", "--parallel", help="Use multiple threads (default: False)", action="store_true")
    parser.add_argument("-d", "--debug", help="Enable debug prints", action="store_true")
    args = parser.parse_args()
    protocol = "TCP"
    if args.udp:
        protocol = "UDP"
    inou = Inou(args.ip_address, args.port, protocol, args.ssl, args.parallel, args.debug)
    result = str(inou.detectService())
    if result == "":
        result = "UNKNOWN"
    print("Result: " + result)


main()
