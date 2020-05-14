# Inou
Inou (pronounced as "I know you") is a tool to discover the service behind a specific unknown port.
It performs an active scan trying to communicate with the service using multiple protocols (even concurrently).
Inou is easy to integrate in bigger frameworks.

## Features
Inou can perform the requests over SSL, UDP and TCP.
The following are the supported protocols:
*  HTTP
*  DNS
*  SIP
*  RTSP
*  FTP
*  SMB
*  SMTP
*  SNMP
*  TELNET
*  SSH
*  SIP
*  ZMQ

Moreover it supports the detection of custom protocols based on JSON, XML or binary data.

## Usage
```
$ python3 inou.py -h
usage: inou.py [-h] [-u] [-s] [-p] [-d] ip_address port

positional arguments:
  ip_address      Target ip address where the service is installed
  port            Target port address where the service is listening

optional arguments:
  -h, --help      show this help message and exit
  -u, --udp       Use UDP instead of TCP
  -s, --ssl       Use SSL sockets (default: False)
  -p, --parallel  Use multiple threads (default: False)
  -d, --debug     Enable debug prints

$ python3 inou.py 127.0.0.1 4443 --ssl -p
Result: HTTP/SSL 
```


## Contributing

Adding the support for a new protocol is enough simple. You have just to implement a new method in the class `Inou` called `is<protocol_name_uppercase>` (e.g. `isFOO`). Then you call `getresponse` method checking the result. The function returns an array of byte, thus use `decode()` if you want to work with strings.

## License

GPLv3
