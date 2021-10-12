from others import color

class HOST:
    """
        desc：初始化
        input：host_info 字典
        output：HOST实体
    """
    def __init__(self,host_info) -> None:
        self.host_ip=host_info['ip'] # str
        self.host_os=host_info['os'] # str
        self.host_port=host_info['port']# str-list
        self.host_service=host_info['service']# str-list
        self.host_vul=host_info['vul']# str-list
        self.color=color()
    """
        设置打印日志的颜色
    """
    def print_color(self,s,c='\033[92m'):
        self.color.print_color(s,c)

    """
        desc：进行攻击
        input: 
            client：msf客户端
            local_ip：本地ip
            command：执行的命令
        output:
            是否攻击成功
    """
    def attack(self,client,local_ip,command):
        self.print_color('Start attacking: '+self.host_ip,self.color.RED)
        for cishu in range(10):
            # 选择一个漏洞
            for vul in self.host_vul:
                result,flag=vul.start_exp(client,local_ip,self,command) # 选msf or python_exp
                if flag.find('flag')!=-1:
                    self.print_color('flag found:'+flag,self.color.GREEN)
                else:
                    self.print_color('flag wrong:'+flag,self.color.GREEN)
                if result==1:##输出scuucess不代表对
                    self.print_color('success exploit '+vul.vul_name,self.color.YELLOW)
                    return True

                self.print_color('failed exploit '+vul.vul_name+',times = '+str(cishu),self.color.BOLD)
        return False
#
# if __name__ == "__main__":
#     h = HOST({"ip":"1,2,3,4", "os":"1,2,3,4","port":"1,2,3,4","service":"1,2,3,4","vul":"1,2,3,4"})
#     h.attack("1,2,3,4","1,2,3,4","1,2,3,4")


    
