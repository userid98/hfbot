# AutoProxy开发文档

## 介绍

AutoProxy是自动代理的工具。目前工具基于调用vemon完成。目标是自动实现内网渗透过程中节点的代理功能。

AutoProxy运行在Linux主机，需要环境：Python、Python库：pwntools

### 使用方法



### 具体介绍

当前功能流程：



当前代码结构：



当前API：

## 当前任务

| 功能     | 完成情况    | 人员         |
| -------- | ----------- | ------------ |
| 启动功能 | ✅           | sofr、Cherry |
| 添加节点 | ✅           | sofr、Cherry |
| 展示节点 | ✅           | sofr、Cherry |
| 日志功能 | ✅ | Cherry       |
| 代理功能 | ✅ |  |
| 监测功能 | ✅ |  |



## 开发进度

### 代理功能

完成并测试完成

需要的参数，1、需要代理的ip，

过程：

1、调用goto n到某个节点 

2、调用venom的socks功能

3、修改proxychains的配置文件 /etc/proxychains.conf

---

需要改进

> 

### 监测功能

完成并测试完成

监测代理情况，记录当前有哪些节点，如果有节点掉了就输出Lost connect：ip

---

需要改进

> 

### 日志功能（18号✅）

完成并测试完成

1、程序的展示节点功能和添加节点功能已完成日志记录

2、日志保存于log文件夹下log.txt文件

---

需要改进

> 

### 启动功能（16号✅）

完成并测试完成

1、首先本地启动fake agent程序，监听本地的端口

2、调用venom的admin程序连接本地的fake agent。（这里的目的是使admin程序启动起来，使本地作为1号节点）

---

需要改进

> 

### 添加节点功能（16号✅）

完成并测试完成

1、通过调用venom的admin程序的connect命令，连接新的主机

2、添加节点时，向字典TargetIp里面加上数字和ip的映射关系	

---

需要改进

> 

### 展示节点功能（16号✅）

完成并测试完成

1、通过调用venom的admin程序的show命令，展示当前已连接到admin上的主机

2、优化节点展示的功能，当前的节点展示只有1，2，3这样的数字样式，把ip信息添加上去。

---

需要改进

> 
