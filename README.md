# lite-capture
基于Netfilter的IP报文捕获器 | HUSTCSE网络安全程序设计

> 开发测试环境
> 
> 内核: 5.15.0-125-generic
> 
> 发行版: Ubuntu 22.04.5 LTS
> 
> 编译器: gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)
>
> 软件包依赖: libpcap-dev

```
lite-capture v1.0

Usage: lite-capture [-hv] [-i interface] [-f file] [-w file]
Options:
  -h
    show help infomation
  -v
    verbose mode, show captured packet ditails
  -i interface
    interface for capturing packets, default all interface
  -f filters
     filter rules for capture
  -w file
    output pcap file

Filters:
  PROTOCAL SRC_ADDR DST_ADDR[;PROTOCAL SRC_ADDR DST_ADDR]
    PROTOCAL: ICMP UDP TCP ANY
    ADDR: 0.0.0.0/0:0
    example: 'ICMP 192.168.0.0/16 10.0.0.0/8;TCP 0.0.0.0/0:0 0.0.0.0/0:0;UDP 192.168.0.1:1234 0.0.0.0/0:0'
    example: 'ANY 0.0.0.0/0:0 0.0.0.0/0:0'
```
