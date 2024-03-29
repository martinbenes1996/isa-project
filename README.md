# ISA Project

Project consists of following files

* README
* lib.h
* netlib.h
* sniffer.h
* myripsniffer.cpp
* myripresponse.cpp
* Makefile
* manual.pdf

This project are two separate programs: myripsniffer and myripresponse.
To compile, type

    $ make

## MyRipSniffer

**myripsniffer** listens on the given interface and catches RIP communication coming through.
It uses {\it libpcap} library. The usage of the program is:

    $ sudo ./myripsniffer -i <interface> [-v|--verbose] [-l|--link] [-n|--network] [-t|--transport]
        -i      Interface program listens to.
        -v      Shows routing data.
        -l      Shows source and destination on the link layer (MAC Addresses).
        -n      Shows source and destination on the network layer (IPv4/IPv6 Addresses).
        -t      Shows source and destination on the transport layer (Ports).

### Example

```
$ sudo ./myripsniffer -i enp0s8
(1) RIPng packet
L7 (RIPng):             Response
+ Routing Table Data
...
```


## MyRipResponse

**myripresponse** generates traffic to the interface causing that all the routers with
RIPng support listening to the link receive fake route and put it in their routing tables.
The usage of program:

    $ ./myripresponse -i <interface> -r <IPv6>/[16-128] {-n <IPv6>} {-m [0-16]} {-t [0-65535]}
        -i      Interface program generates traffic on.
        -r      Fake route address/subnet prefix.
        -n      Next route. Defaultly ::.
        -m      Metric. Defaultly 1.
        -t      Route tag. Defaultly 0.

### Example

```
$ sudo ./myripresponse -i enp0s8 -r 2001:db8:0:abcd::/64
Sent RIP Response.
Sent RIP Response.
Waiting 30 s [##         ]
```



