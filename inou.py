#! /usr/bin/env python3

import argparse
import socket
import sys
import ssl
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

class ConnManager:
    """ Connection Manager Class """

    def connect(self):
        """
        This method closes previously opened connections and makes a new connection
        to the target service using the specified transport protocol (UDP/TCP/SSL)
        """
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
        """
        This method is used to check if the service has replied to the messages belonging to a specific protocol.
        data : is a string or a bytearray that we send to the service
        length : is the size of the response we need to perform our checks about its validity
        binary : says if we need to interpret data as binary data (true) or as a string (false)
        The method return always a byte array with the specified length or empty if the service didn't reply
        If you need to interpret the response as a string use getresponse(...).decode()
        """
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

    def isDNS(self, cm):
        # DNS Query A www.google.com
        data = b"\x59\xf6\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
        return cm.connect() and (cm.getresponse(data, 4, True) == b"\x59\xf6\x81\x80")

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

    def isSMB(self, cm):
        # SMB Negotiate Protocol Request
        data = (b"\x00\x00\x00\x9b\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8" \
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe" \
                b"\x00\x00\x00\x00\x00\x78\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f" \
                b"\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02" \
                b"\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f" \
                b"\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70" \
                b"\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30" \
                b"\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54" \
                b"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e" \
                b"\x30\x30\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00")
        #The response will start with \x00, if we use .decode() we get an empty string
        return cm.protocol == "TCP" and cm.connect() and (b"SMB" in cm.getresponse(data, 10, True))

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
        data = b"\xff\xfb\x18\xff\xfb\x20\xff\xfb\x23\xff\xfb\x27"
        if cm.protocol == "TCP" and cm.connect():
            resp = cm.getresponse(data,2,True)
            return len(resp) == 2 and (resp[0] == 0xff) and (resp[1] > 0xf0)
        return False

    def isSSH(self, cm):
        data = "SSH-1.99-Cisco-1.25\n"
        if cm.connect():
            response = cm.getresponse(data, 3).decode()
            #GetResponse can return data of the application banner sent 
            return cm.protocol == "TCP" and (response == "SSH") or (len(response) > 0 and response[0] == "\x00")
        return False

    def isRABBITMQ(self, cm):
        data = (b"\x00\x30\x4e\x00\x00\x00\x01\x01\xdf\x7f\xbc\x5e\xc3\xcf\x9e\x00"
                b"!rabbitmqcli-2538-rabbit@localhost")
        return cm.protocol == "TCP" and cm.connect() and cm.getresponse(data, 5, True) == b"\x00\x03\x73\x6f\x6b"

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
        result = cm.connect() and (len(cm.getresponse(data, 1, True)) > 0)
        if (result == False):
            #Try again sending the memory layout of struct { int; int; int; int}
            data = b'\x00\x00\x00\x01\x00\x00\x00\x02\x00\xff\x05\x03\x00\x00\x00\x04'
            result = cm.connect() and (len(cm.getresponse(data, 1, True)) > 0)
        return result
    
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
