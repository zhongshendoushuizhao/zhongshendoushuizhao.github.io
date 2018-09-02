---
layout:     post
title:      Xcode命令行工具管理
subtitle:   如何切换Xcode命令行工具
date:       2018-05-05
author:     BY
header-img: img/post-bg-kuaidi.jpg
catalog: true
tags:
    - Xcode
    - iOS
---

## 安装

	xcode-select --install



## Xcode版本切换

### 显示当前使用的xocde版本

	$ xcode-select --print-path

### 选择Xcode中的默认版本

	$ sudo xcode-select -switch /Applications/Xcode.app