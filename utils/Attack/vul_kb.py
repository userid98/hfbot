# -*- coding: utf-8 -*
from py2neo import Graph,Node,Relationship,NodeMatcher,RelationshipMatcher
import re
import pandas as pd
from vulneriablity import VULNERIABLITY
# from JudgeRange import JUDGE

import platform  # changed by hdd 
import sys, os
import logging
sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# log
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.basename(__file__)[:-3]+".log", mode='a')
formatter = logging.Formatter("%(asctime)s -  %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# log

class  VUL_KB:
    """
        desc：初始化连接图数据库
    """
    def __init__(self) -> None:
        # 连接图数据库
        try:
            self.graph = Graph("http://localhost:7474", auth=("neo4j", "hfbot"))
        except:
            print ("Neo4j service down")
        # 建立一个节点查询器
        self.node_matcher = NodeMatcher(self.graph)
        # python匹配图数据库的关系
        self.rel_matcher=RelationshipMatcher(self.graph)
        #用于利用web应用判断漏洞
        self.sensitive_web_services=['WebLogic','Struts2','Tomcat','WordPress','Nagios','SMBv1','SimpleCalenda','Supervisor XML-RPC server','libssh','Drupal','CouchDB','SquadManagement','vBulletin','ZZZCMS zzzphp','ForgeRock Access Manager','VMware vCenter Server','VMware vRealize-SSRF','RDP','FTP']
        #用于直接利用端口判断漏洞
        self.sensitive_system_port=['445','3389','21','9001','2222','8080','5984','7001','25','80','5432','443','8009']
        #用于判断可能的弱口令漏洞
        self.sensitive_ports_weak_password=['21']
        
    """
        desc:处理扫描获得的基本信息
        input: 端口号，服务，操作系统列表
        output: web漏洞、系统漏洞、弱口令漏洞
    """
    def handle_base_info(self,ports,services,os):
        '''
        敏感服务：WebLogic,Strusts2,Tomcat,WordPress,Nagios.....(端口不定)
        敏感端口:21(FTP),22(SSH),139(Samba),445(SMB)
        '''
        # re_version=r"\d+(\.\d+)+"
        # 提取版本号的正则表达式，目前只能提取离散值
        re_version=r'\d+\.(?:\d+\.)*\d+'
        sensitives_web_vul=[]
        sensitives_weak_password=[]
        sensitives_system_vul=[]
        for item in range(len(services)):
            service=services[item].split('&')
            if service[0].find('http')!=-1:
                for s in self.sensitive_web_services:
                    if service[1].find(s)!=-1:
                        sensitive_info={}
                        sensitive_info['port']=ports[item]
                        sensitive_info['service']=s
                        sensitive_info['OS']=os
                        version=re.findall(re_version,service[1])
                        if len(version)==0:
                            version='no version'
                        else:
                            version=version[0]
                        sensitive_info['version']=version
                        #logger.info(sensitive_info)
                        sensitives_web_vul.append(sensitive_info)
        #for p in self.sensitive_ports:
        for item in range(len(ports)):           
            for p in self.sensitive_ports_weak_password:
                if ports[item].find(p)!=-1:
                    service=services[item].split('&')
                    sensitive_info={}
                    sensitive_info['port']=ports[item]
                    sensitive_info['service']=service[0]
                    sensitive_info['OS']=os
                    #logger.info(sensitive_info)
                    sensitives_weak_password.append(sensitive_info)
        for item in range(len(ports)):
            for p in self.sensitive_system_port:
                if ports[item].find(p)!=-1:
                    service=services[item].split('&')
                    sensitive_info={}
                    sensitive_info['port']=ports[item]
                    sensitive_info['service']=service[0]
                    sensitive_info['OS']=os
                    #logger.info(sensitive_info)
                    sensitives_system_vul.append(sensitive_info)
        #logger.info(sensitives_web_vul)
        #logger.info(sensitives_system_vul)
        #logger.info(sensitives_weak_password)
        return sensitives_web_vul,sensitives_system_vul,sensitives_weak_password
    
    # 
    def cypher_run(self,str):
        return self.graph.run(str)

    def get_target_match_vuls(self,checkver,inputlist):
        judger = JUDGE(checkver,inputlist)
        return judger.start_judge()

    # WEB应用漏洞
    def match_web_vuls(self,sensitive_web_vul):
        web_vul_lists=[]
        for w in sensitive_web_vul: 
            port=w['port']
            service=w['service']
            version=w['version']
            os=w['OS']
            
            # 原先的
            # target=service+' '+version22


            target_type=['WebLogic','Struts2','Tomcat','WordPress','Nagios','SMBv1','SimpleCalenda','Supervisor XML-RPC server','libssh','Drupal','CouchDB']
            service = service.lower()
            for t in target_type:
                if service.find(t)!=-1:
                    service=t
            # 改成 之更具name来匹配
            match_str="match(n:VULNERABILITY)-[r:attack]-(m:TARGET) where m.name=~'%s' return m,n" %(service+'.*')##根据服务和版本确定的候选列表
            web_vul_list=self.cypher_run(match_str).data()

            #   扫描到的data为空时 直接返回
            if '' == web_vul_list:
                return
            logger.info(web_vul_list[0]['m']['ver'])
            vuls = []
            #vul_node=vul[0]['n']['name']
            for index in range(0,len(web_vul_list)):
                tag= self.get_target_match_vuls(version,web_vul_list[index]['m']['ver'])
                if tag :
                    vuls.append(web_vul_list[index]['n'])

            for v_node in vuls:
                vul_info={}
                # v_node=v['n']
                match_str="match(n:VULNERABILITY)-[r:affect]-(m:OS) where n.name='%s' return m" %(v_node['name'])
                OS_match_list=self.cypher_run(match_str).data()
                os_if_match=0
                for i in range(len(OS_match_list)):
                    OS=OS_match_list[i]['m']['name']       

                    if OS=='*' or OS.find(os)!=-1:##根据操作系统进一步筛选
                        os_if_match=1
                        match_str="match(n:VULNERABILITY)-[r:cause]-(m:CONSEQUENCE) where n.name='%s' return m" %(v_node['name'])
                        temp=self.cypher_run(match_str).data()[0]['m']
                        consequence=temp['name']
                        access=temp['access']
                        match_str="match(n:VULNERABILITY)-[r:has_exp]-(m:EXP) where n.name='%s' return m" %(v_node['name'])
                        exp=self.cypher_run(match_str).data()[0]['m']['name']

                        vul_info['name']=v_node['name']
                        vul_info['CVSS_score']=v_node['cvss_score']
                        vul_info['attack_vector']=v_node['attack_vector']
                        vul_info['service']=service+':'+version
                        vul_info['port']=port
                        vul_info['OS']=OS
                        vul_info['consequence']=consequence
                        vul_info['exp_id']=exp
                        vul_info['access']=access
                        logger.info('可能存在漏洞：')
                        logger.info(vul_info)
                        new_vul=VULNERIABLITY(vul_info)
                        web_vul_lists.append(new_vul)
                if os_if_match==0:
                    logger.info(v_node['name']+':操作系统不匹配')

        return web_vul_lists
    
    #系统应用漏洞
    def match_system_vuls(self,sensitive_system_vul):
        system_vul_list=[]
        for s in sensitive_system_vul:
            port=s['port']
            os=s['OS']
            service=s['service']
            ##根据端口确定MS17010  OR  MS08067
            match_str="match(n:VULNERABILITY)-[r:need]-(m:PORT) where m.name='%s' return n" %port
            sys_vul=self.cypher_run(match_str).data()
            for v in sys_vul:
                vul_info={}
                v_node=v['n']
                match_str="match(n:VULNERABILITY)-[r:affect]-(m:OS) where n.name='%s' return m" %(v_node['name'])
                OS_match_list=self.cypher_run(match_str).data()
                os_if_match=0 #标记操作系统是否匹配情况
                for i in range(len(OS_match_list)):
                    OS=OS_match_list[i]['m']['name']
                    if OS=='*' or OS.find(os)!=-1:##根据操作系统进一步筛选
                        os_if_match=1
                        match_str="match(n:VULNERABILITY)-[r:cause]-(m:CONSEQUENCE) where n.name='%s' return m" %(v_node['name'])
                        temp=self.cypher_run(match_str).data()[0]['m']
                        consequence=temp['name']
                        access=temp['access']
                        match_str="match(n:VULNERABILITY)-[r:has_exp]-(m:EXP) where n.name='%s' return m" %(v_node['name'])
                        exp=self.cypher_run(match_str).data()[0]['m']['name']
                        vul_info['name']=v_node['name']
                        vul_info['CVSS_score']=v_node['cvss_score']
                        vul_info['attack_vector']=v_node['attack_vector']
                        vul_info['service']=service
                        vul_info['port']=port
                        vul_info['OS']=OS
                        vul_info['consequence']=consequence
                        vul_info['exp_id']=exp
                        vul_info['access']=access
                        logger.info('可能存在漏洞：')
                        logger.info(vul_info)
                        new_vul=VULNERIABLITY(vul_info)
                        system_vul_list.append(new_vul)
                if os_if_match==0:
                    logger.info(v_node['name']+':操作系统不匹配')
            
        #logger.info(sensitive_system_vul)
        return system_vul_list

    def match_weak_password(self,sensitive_weak_password):
        '''
        弱口令破解
        需要指定目标IP，已知目标机开启的服务&端口
        input：目标主机信息
        output： sing， 用户名&密码list
        '''
        wp_vul_list=[]
        ip = sensitive_weak_password['ip']

        my_os = platform.architecture()
        if my_os == ('32bit', 'WindowsPE'):
            import xcrack.win32.xcrack as crack
        elif my_os == ('64bit', 'WindowsPE'):
            import xcrack.win64.xcrack as crack
        elif my_os == ('32bit', 'ELF'):
            import xcrack.linux32.xcrack as crack
        elif my_os == ('64bit', 'ELF'):
            import xcrack.linux64.xcrack as crack

    
        for port in sensitive_weak_password['port']: #将47个漏洞里边已知的系统漏洞列到表格里，然后用目标及的系统信息去匹配
            service = {
                '21' : 'ftp',
                '22' : 'ssh',
                '445': "smb",
            }
            serve = service.get(port, None)
            if serve is None:
                continue
            else:
                #调用当前下载到本地的xcrack

                rs = crack.PwdCrack(ip, port, serve)
                if rs !='':
                    logger.info('弱口令破解成功')
                    sign = 'Success'
                    break
                    
                else:
                    logger.info('弱口令破解失败')
                    sign = 'Faile'
                    rs = ''
                    break

                
        return sign, rs

    """
        desc：根据主机信息进行匹配漏洞
        input：主机信息
        output：三个列表
            web_vul_list WEB应用漏洞
            system_vul_list 
            wp_vul_list 弱口令
    """
    def match_vuls(self,host_info):
        vul_list=[]
        ports,services,os=host_info['port'],host_info['service'],host_info['os']
        sensitive_web_vul,sensitive_system_vul,sensitive_weak_password=self.handle_base_info(ports,services,os)
        # WEB应用漏洞
        web_vul_list=self.match_web_vuls(sensitive_web_vul)
        # 系统
        system_vul_list=self.match_system_vuls(sensitive_system_vul)
        # 弱口令
        #wp_vul_list=self.match_weak_password(sensitive_weak_password)
        return web_vul_list,system_vul_list


class JUDGE:
    
    # 只输入 待判断版本号 和 版本区间
    def __init__(self,checkinput,tablelist) -> None:
        self.checkinput = checkinput
        if tablelist != "no version":
            self.inputRangelist = tablelist.split(';')
        else:
            self.inputRangelist = tablelist
        self.isInRange = False

    # 正则表达式判断版本号是否在这区间  1-2
    def checkCloseRange( self,input, checkInput):
        rangeleft = input.split('-')[0]
        rangeleftArray = rangeleft.split('.')
        rangeright = input.split('-')[1]
        rangerightArray = rangeright.split('.')

        checkInputArray = checkInput.split('.')

        return self.compareTwoSide(rangeleftArray, checkInputArray) and self.compareTwoSide(checkInputArray, rangerightArray)


    '''
    开区间、半开区间
    '''


    def checkOpenRange(self,range, checkInput):
        rangeArray = [ch for ch in range]
        rangelen = len(range)
        removeSE = range[1:rangelen - 1]
        rangeleft = removeSE.split(',')[0]
        rangeright = removeSE.split(',')[1]
        if '[' == rangeArray[0]:
            if rangeleft == checkInput:
                return True
        elif ']' == rangeArray[rangelen - 1]:
            if rangeright == checkInput:
                return True
        rangeleftArray = rangeleft.split('.')
        rangerightArray = rangeright.split('.')
        checkInputArray = checkInput.split('.')
        if rangeleft == 'MIN' and rangeright == 'MAX':
            return True
        if rangeleft == 'MIN':
            return self.compareTwoSide(checkInputArray, rangerightArray)
        elif rangeright == 'MAX':
            return self.compareTwoSide(rangeleftArray, checkInputArray)
        else:
            # 两边都需要比较 都为真才是在区间内
            return  self.compareTwoSide(rangeleftArray, checkInputArray) and  self.compareTwoSide(rangerightArray, checkInputArray)


    def compareTwoSide(self,leftArray, rightArray):
        checklen = min(len(leftArray), len(rightArray))
        for i in range(0, checklen):
            if int(leftArray[i]) > int(rightArray[i]):
                return False
            elif int(leftArray[i]) <= int(rightArray[i]):
                continue
        return True


    '''
    检测 离散值内
    '''


    def checkDistributeRange(self,rangedb, checkInput):
        checklen = len(checkInput)
        rangeArray = rangedb.split(',')
        logger.info(len(rangeArray))
        rangelen = len(rangeArray[0])
        if checklen >= rangelen:
            checkInput = checkInput[0:rangelen]
        else:
            for t in range(0,len(rangeArray)):
                rangeArray[t] = rangeArray[t][0:checklen]
        if checkInput in rangeArray:
            return True
        return False


    '''
    开区间 () [] 、闭区间、离散值
    '''


    def checkFunction(self,oneRange):
        oneRangeChars = [ch for ch in oneRange]  # oneRange.split('')
        firstSymbol = oneRangeChars[0]
        if firstSymbol == '(' or firstSymbol == '[':
            return 'open_range'
        elif '-' in oneRangeChars:
            return 'close_range'
        elif ',' in oneRangeChars:
            return 'distribute_range'

        logger.info(oneRange)
        return None



    def start_judge(self):
        # chargeinput = 'strust2:2.3.6'
        # inputRange2 = '(MIN,MAX)'
        # inputRange = '(MIN,2.1.1];2.2.1,2.2.2;2.3.5-2.3.31;2.5.0-2.5.10;(3.0.0,MAX)'
        # inputRangelist = inputRange.split(';')
        # maohaolocation = chargeinput.find(':')
        # chargeinputlen = len(chargeinput)
        # checkinput = chargeinput[maohaolocation + 1:chargeinputlen]
        # isInRange = False

        if self.checkinput == 'no version':
            self.isInRange = True
            return self.isInRange

        if self.inputRangelist == 'no version':
            self.isInRange = True
            return self.isInRange

        for oneRange in  self.inputRangelist:
            rangeSymbol = self.checkFunction(oneRange)  # 找到需要调用的方法
            if rangeSymbol == 'close_range':
                self.isInRange =  self.checkCloseRange(oneRange,  self.checkinput)
                if self.isInRange:
                    logger.info('在区间内', oneRange)
                    break
            elif rangeSymbol == 'open_range':
                self.isInRange =  self.checkOpenRange(oneRange,  self.checkinput)
                if self.isInRange:
                    logger.info('在区间内', oneRange)
                    break
            elif rangeSymbol == 'distribute_range':
                self.isInRange =  self.checkDistributeRange(oneRange,  self.checkinput)
                if self.isInRange:
                    logger.info('在区间内', oneRange)
                    break

        if self.isInRange:
            logger.info('在区间内')
        return  self.isInRange