#-*- coding: utf-8 -*-
import sys
import os
import csv

"""
desc：nmap执行命令，将扫描结果输出为txt
input：IP地址、命令行代码
output：无
"""
def run_nmap_scan(IP,command):
    os.system('nmap -oN scan_result.txt '+command+' '+IP+"\n")

"""
desc：读文件获取各个目标的主机信息、端口号、状态、服务、服务版本等
input：文件路径
output：输出各个目标信息的列表、字典等
"""
def Read_Files(filename):
    #统计所有的IP地址，存储在列表中
    IP_addresses=[]  
    #将扫描结果按照字典的形式存储在字典中
    IP_port_dict=dict()  
    IP_host_dict=dict()
    IP_NetBIOSname_dict=dict()
    IP_NetBIOSMAC_dict=dict()
    IP_OS_dict=dict()
    #里面为0则IP不存活，为1则IP存活
    ip_live=[] 
    with open(filename, 'r') as f:
        #序号i用来标记第几个IP地址，来读取该IP地址的扫描结果
        i = -1  
        #当前读取txt文件的行号
        line_num=0 
        #用来判断是否是http服务，同时用端口号为其赋值
        http_flag=-1 

        for line in f.readlines():
            line_num=line_num+1
            #一般认为该行是一个IP地址扫描结果的开始
            if "Nmap scan report for" in line:  
                #IP地址在该行字符串for后面
                IP_addresses.append(line[line.find("for")+4:-1])  
                i = i + 1
                #假设其不存活，若有端口之类的信息，再将其设置为1
                ip_live.append(0)

                # 有些端口全部关闭的IP的以下也被赋值为空格，写入CSV时，大循环外按照IP_port_dict进行查找即可不写入
                IP_host_dict[IP_addresses[i]+'_host']=" "
                IP_NetBIOSname_dict[IP_addresses[i]+'_NetBIOSname']=" "
                IP_NetBIOSMAC_dict[IP_addresses[i]+'_NetBIOSMAC']=" "
                #操作系统信息可能出现多次，以下为可能出现的操作系统信息
                IP_OS_dict[IP_addresses[i] + "_OS"] = " "
                IP_OS_dict[IP_addresses[i]+"-smb-os"]=" "   #smb-os-discovery
                IP_OS_dict[IP_addresses[i]+"-smb-os-line-num"] =-1
                IP_OS_dict[IP_addresses[i] + "-service-info-os"] = " "    #Service Info: OSs:或Service Info: OS：

            #以下的if为读取端口号，状态，服务，服务版本
            if line[0]>='0' and line[0]<='9' and len(line.split())>=1 and '/' in line.split()[0]:  #该行第一个字符为数字时且第一个空格前有斜线，可能为扫描到的端口信息
                ip_live[i] = 1   #IP存活
                if len(line.split())>=4:    #当version不为空
                    port,state,service,version=line.split()[0][:line.split()[0].find('/')],line.split()[1],line.split()[2],line[line.find(line.split()[3]):-1]  #将该行信息按照空格分开
                elif len(line.split())==3:
                    port,state,service,version=line.split()[0][:line.split()[0].find('/')],line.split()[1],line.split()[2]," "
                elif len(line.split())==2:
                    port,state,service,version=line.split()[0][:line.split()[0].find('/')],line.split()[1]," "," "
                else:
                    port,state,service,version=line.split()[0][:line.split()[0].find('/')]," "," "," "
                IP_port_dict[IP_addresses[i]+'_'+port]=[int(port),state, service, version]  #将该行信息以IP地址+端口为key值存储在字典中
                if "http" in service:
                    http_flag=int(port)

            #若有http-title则将其与version联系在一起
            if "http-title" in line and "Error 404" not in line and "Site doesn't have a title" not in line and http_flag!=-1:
                before_version=IP_port_dict[IP_addresses[i]+'_'+str(http_flag)][3]
                new_version=line[line.find(":")+1:-1]+" & "+before_version
                IP_port_dict[IP_addresses[i] + '_' + str(http_flag)][3]=new_version
                http_flag=-1

            #以下的if为读取文件中所有可能存在的操作系统类型
            if 'smb-os-discovery' in line:
                ip_live[i] = 1  #IP存活
                IP_OS_dict[IP_addresses[i]+"-smb-os-line-num"] =line_num

            if 'OS' in line and IP_OS_dict[IP_addresses[i]+"-smb-os-line-num"]+1==line_num:
                IP_OS_dict[IP_addresses[i] + "-smb-os"] =line[line.find(":")+1:-1]
                IP_OS_dict[IP_addresses[i] + "-smb-os-line-num"]=-1

            #IP地址的主机信息
            if 'Service Info' in line and 'OS' in line:
                ip_live[i] = 1  #IP存活
                temp_str=line[line.find('OS'):]
                #读取主机信息
                os_info=temp_str[temp_str.find('OS')+4:temp_str.find(';')]
                IP_OS_dict[IP_addresses[i] + "-service-info-os"]=os_info  

            # 以下的顺序为当多处有操作系统信息时的优先级
            # IP_OS_dict[IP_addresses[i] + "_OS"]存的是每个IP最终选择的操作系统类型
            # 读取最开始几行没有该列表，在读到Nmap scan report for才创建
            if i>=0:
                if IP_OS_dict[IP_addresses[i] + "-smb-os"]!=" ":
                    IP_OS_dict[IP_addresses[i] + "_OS"] =IP_OS_dict[IP_addresses[i] + "-smb-os"]
                elif IP_OS_dict[IP_addresses[i] + "-service-info-os"]!=" ":
                    IP_OS_dict[IP_addresses[i] + "_OS"] =IP_OS_dict[IP_addresses[i] + "-service-info-os"]
                else:
                    IP_OS_dict[IP_addresses[i] + "_OS"] =" "
                # 以下对Linux系统名称进行规范化
                if "Linux" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                    IP_OS_dict[IP_addresses[i] + "_OS"]="Linux"
                #以下对Windows系统名称进行规范化
                if "Windows" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                    # Windows XP一系列版本
                    if "XP" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                        if "SP3" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 3" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"]="Windows XP SP3"
                        elif "SP2" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 2" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows XP SP2"
                        elif "SP1" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 1" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows XP SP1"
                        else:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows XP"
                    # Windows Vista一系列版本
                    elif "Vista" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                        if "SP1" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 1" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"]="Windows Vista SP1"
                        elif "SP2" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 2" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows Vista SP2"
                        else:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows Vista"
                    # Windows 7一系列版本
                    elif "Windows 7" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                        if "Beta" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"]="Windows 7 Beta"
                        elif "SP1" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 1" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows 7 SP1"
                        else:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows 7"
                    # Windows 8.1
                    elif "Windows 8.1" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                        IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows 8.1"
                    # Windows 8
                    elif "Windows 8" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                        IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows 8"
                    # Windows 10
                    elif "Windows 10" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                        IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows 10"
                    elif "Server" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                        if "2003" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            if "SP1" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 1" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                                IP_OS_dict[IP_addresses[i] + "_OS"]="Windows Server 2003 SP1"
                            elif "SP2" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 2" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                                IP_OS_dict[IP_addresses[i] + "_OS"]="Windows Server 2003 SP2"
                            else:
                                IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows Server 2003"
                        if "2008" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            if "SP1" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 1" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                                IP_OS_dict[IP_addresses[i] + "_OS"]="Windows Server 2008 SP1"
                            elif "SP2" in IP_OS_dict[IP_addresses[i] + "_OS"] or "Service Pack 2" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                                IP_OS_dict[IP_addresses[i] + "_OS"]="Windows Server 2008 SP2"
                            else:
                                IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows Server 2008"
                        if "2012" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows Server 2012"
                        if "2016" in IP_OS_dict[IP_addresses[i] + "_OS"]:
                            IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows Server 2016"
                    else:
                        IP_OS_dict[IP_addresses[i] + "_OS"] = "Windows"



            if 'Service Info' in line and 'Host:' in line:   #该行一般为该IP地址的主机信息
                temp_str = line[line.find('Host:'):]
                # 主机信息
                host_info=temp_str[temp_str.find('Host:')+5:temp_str.find(';')]  
                IP_host_dict[IP_addresses[i]+'_host']=host_info.strip()
            if  'nbstat' in line and 'NetBIOS name' in line:
                temp_str = line[line.find('NetBIOS name'):]
                # 主机信息
                netbiosname_info=temp_str[temp_str.find('NetBIOS name')+13:temp_str.find(',')] 
                IP_NetBIOSname_dict[IP_addresses[i]+'_NetBIOSname']=netbiosname_info.strip()
            if  'nbstat' in line and 'NetBIOS MAC' in line:
                # 主机信息
                netbiosmac_info=line[line.find('NetBIOS MAC')+12:-1]
                IP_NetBIOSMAC_dict[IP_addresses[i]+'_NetBIOSMAC']=netbiosmac_info.strip()
    f.close()
    return IP_addresses,IP_port_dict,IP_OS_dict,IP_host_dict,IP_NetBIOSname_dict,IP_NetBIOSMAC_dict,ip_live

"""
    desc:将获取的主机信息、端口号、状态、服务、服务版本等写入CSV文件
    input: 主机信息、端口号、状态、服务、服务版本的字典、数组
    output: csv文件
"""
def Write_csv(IP_addresses,IP_port_dict,IP_OS_dict,IP_host_dict,IP_NetBIOSname_dict,IP_NetBIOSMAC_dict):
    with open('scan_result.csv','w+') as csvfile:  
        f = csv.writer(csvfile)
        #写入表头
        f.writerow(['ip address','port','state','service & version','os','host','NetBIOS name','NetBIOS MAC'])
        for key in IP_port_dict:
            for key_1 in IP_OS_dict:
                for key_2 in IP_host_dict:
                    for key_3 in IP_NetBIOSname_dict:
                        for key_4 in IP_NetBIOSMAC_dict:
                            if key[0:key.find('_')]==key_1[0:key_1.find('_OS')] and key[0:key.find('_')]==key_2[0:key_2.find('_')] and key[0:key.find('_')]==key_3[0:key_3.find('_')] and key[0:key.find('_')]==key_4[0:key_4.find('_')]:
                                f.writerow([key[:key.find('_')],IP_port_dict[key][0],IP_port_dict[key][1],IP_port_dict[key][2]+' & '+IP_port_dict[key][3],IP_OS_dict[key_1],IP_host_dict[key_2],IP_NetBIOSname_dict[key_3],IP_NetBIOSMAC_dict[key_4]])
    csvfile.close()

"""
desc：根据主机信息、端口号、状态、服务、服务版本等 扫描是否存在漏洞
input: IP信息列表，主机信息、端口号、服务、服务版本等字典
output: 字典 可根据[IP][IP信息类别 如port_list/services_list/os等]进行筛选
"""
def scan_result(IP_addresses, IP_port_dict, IP_os_dict, IP_host_dict, IP_NetBIOSname_dict,ip_live):
    i=0
    scan_dict=dict()
    for input_IP in IP_addresses:
        if ip_live[i]==1:
            scan_dict[input_IP]=dict()
            scan_dict[input_IP]["port_list"] = []
            scan_dict[input_IP]["services_list"] = []
            scan_dict[input_IP]["os"] = []
            scan_dict[input_IP]["host"] = []
            scan_dict[input_IP]["netbiosname"] = []
            for key in IP_port_dict:
                if input_IP in key:
                    scan_dict[input_IP]["port_list"].append(str(IP_port_dict[key][0]))
                    scan_dict[input_IP]["services_list"].append(IP_port_dict[key][2]+' & '+IP_port_dict[key][3])
            for key in IP_os_dict:
                if input_IP+ "_OS"==key:
                    scan_dict[input_IP]["os"].append(IP_os_dict[key])
            for key in IP_host_dict:
                if input_IP+"_host"==key:
                    scan_dict[input_IP]["host"].append(IP_host_dict[key])
            for key in IP_NetBIOSname_dict:
                if input_IP+"_NetBIOSname"==key:
                    scan_dict[input_IP]["netbiosname"].append(IP_NetBIOSname_dict[key])
        i=i+1
    return scan_dict

"""
desc：扫描
input：IP地址和命令符
output：字典 可根据[IP][IP信息类别 如port_list/services_list/os等]进行筛选信息
"""
def nmap_scan(IP,command):
    # 使用nmap扫描获取scan_result.txt
    run_nmap_scan(IP,command)
    # 如果命令符为 -A 
    if command=='-A':
        IP_addresses, IP_port_dict, IP_OS_dict, IP_host_dict, IP_NetBIOSname_dict, IP_NetBIOSMAC_dict,ip_live=Read_Files("scan_result.txt")
        Write_csv(IP_addresses, IP_port_dict, IP_OS_dict, IP_host_dict, IP_NetBIOSname_dict, IP_NetBIOSMAC_dict)
        scan_dict=scan_result(IP_addresses, IP_port_dict, IP_OS_dict, IP_host_dict, IP_NetBIOSname_dict,ip_live)
        return scan_dict

