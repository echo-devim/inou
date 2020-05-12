# Inou

Inou (pronounced as "I know you") is a tool to discover the service behind a specific unknown port.
It performs an active scan trying to communicate with the service using multiple protocols (even concurrently).
Inou is easy to integrate in bigger frameworks.

## Features
Inou can perform the requests over SSL, UDP and TCP.
The following are the supported protocols:
*  HTTP
*  SIP
*  RTSP
*  FTP
*  SMTP
*  TELNET
*  SSH
*  SIP
*  ZMQ

Moreover it supports the detection of custom protocols based on JSON, XML or binary data.

## Contributing

Adding the support for a new protocol is enough simple. You have just to implement a new method in the class `Inou` called `is<protocol_name_uppercase>` (e.g. `isFOO`). Then you call `getresponse` method checking the result. The function returns an array of byte, thus use `decode()` if you want to work with strings.

## License

GPLv3