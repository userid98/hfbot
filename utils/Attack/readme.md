# HFBOT

本程序功能：实现对可访问的主机的漏洞自动探测和利用

文件和主要模块描述：

0. 主程序 start_attack.py 使用命令行对目标进行扫描攻击;
1. 扫描模块：botnmapscan.py
2. 漏洞知识库：vulkb.py  包含了基本信息处理函数，漏洞的查询和匹配函数
3. 漏洞利用模块: vulneriablity.py  负责处理漏洞利用功能
4. 主机类: host.py，存储目标主机的关键信息
5. 漏洞利用工具存储: tools, vul_tools.json是个工具数据库，存放各个EXP的利用方式，exp文件夹存储EXP文件
6. 漏洞知识库构建: vul_kb，vul_kb.xlsx是漏洞知识库的关系型数据库，create_kb.py将关系型数据转存为图数据库

当前支持的漏洞类型：

- CVE-2017-5638
- CVE-2020-14882
- CVE-2019-2729
- CVE-2019-0232
- MS17-010: Windows XP
- MS08-067: Windows XP

# 运行程序的过程

在程序的目录下 打开终端 输入 python start_attack.py -t 目标ip；
就会依次执行nmap对目标的基本扫描，得到scan_dict字典；
根据字典的key将每个ip对应的基本信息封装成host字典，根据host字典信息匹配数据库中的漏洞，再将匹配到的漏洞放入host字典中进行补充，最终得到一个待攻击的目标列表uncompromised_target；
依次便利待攻击目标进行攻击，攻击成功就退出
