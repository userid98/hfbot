# -*- coding: cp936 -*-
import paramiko
import re, os
import logging
# log
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.basename(__file__)[:-3]+".log", mode='a')
formatter = logging.Formatter("%(asctime)s -  %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# log

def main(ip, login_name, pwd, port=22):
    '''
        功能:
            判别操作系统类型
            读取flag
        input:
            ip, 用户名, 口令(, 端口号)
        output:
            flag内容
    '''
    p = port
    s = paramiko.SSHClient()
    s.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 允许连接不在know_hosts文件中的主机
    s.connect(hostname=ip, port=p, username=login_name, password=pwd)
    stdin, stdout, stderr = s.exec_command('systeminfo')
    stdo_r = str(stdout.read())
    # logger.info('stdo_r-system', stdo_r)
    if 'Windows' in stdo_r:
        path = 'C:/Users/' + login_name + '/Desktop'
        execmd = 'cd ' + path
        logger.info('操作系统类型为windows')
    else:
        stdin, stdout, stderr = s.exec_command('uname -a')
        stdo_r = str(stdout.read())
        # logger.info('stdo_r-uname11', stdo_r)
        if 'Linux' in stdo_r:
            path = '/'
            execmd = 'cd /'
            logger.info('操作系统类型为linux')
        else:
            logger.info('查询操作系统类型错误，程序退出')
            sys.exit()
    # logger.info('execmd:', execmd)
    if 'Users' in path:
        s.close()
        s = paramiko.SSHClient()
        s.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 允许连接不在know_hosts文件中的主机
        s.connect(hostname=ip, port=p, username=login_name, password=pwd)
    stdin, stdout, stderr = s.exec_command(execmd+';ls') if 'Users' in path else s.exec_command(execmd+';ls')
    #stdin, stdout, stderr = s.exec_command('dir')
    stdo_r = stdout.read().decode('unicode_escape')
    # logger.info('stdo_r-dir|ls:', stdo_r)
    # logger.info('stdr_r-dir|ls:', stderr.read().decode('unicode_escape'))
    if 'flag' not in stdo_r:
        logger.info('目录下不存在包含flag命名的文件，程序退出')
        sys.exit()
    flagname = ''
    if 'Users' in path:
        cmp = re.compile('.*flag(?P<flag_ex>.*?)\n')
        flagname = 'flag' + cmp.search(stdo_r).group('flag_ex')
    else:
        stdout_sp = stdo_r.split('\n')
        for i in stdout_sp:
            if 'flag' in i:
                flagname = i
    if flagname == '':
        logger.info('查询flag文件出错，程序退出')
    # logger.info('flagname:', flagname, 'len_flagname:', len(flagname))
    flagpath = path + '/' + flagname if 'Users' in path else path + flagname
    # logger.info('flagpath:', flagpath)
    if 'Users' in path:
        s.close()
        s = paramiko.SSHClient()
        s.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 允许连接不在know_hosts文件中的主机
        s.connect(hostname=ip, port=p, username=login_name, password=pwd)
        stdin, stdout, stderr = s.exec_command(flagpath)
        # logger.info('stderr:', stderr.read())
        cmpl = re.compile(r"line \d: (?P<fl>.+?): command not found")
        rf = cmpl.findall(stderr.read().decode('unicode_escape'))
        # logger.info('rf:', rf)
        if not rf:
            logger.info('读取flag出错，程序退出')
            sys.exit()
        fl_list = []
        for r in rf[:-1]:
            fl_list.append(r[2:-1].replace('\r', '\n'))
        fl_list.append(rf[-1])
        # logger.info('fl_list:', fl_list)
        flag = ''.join(fl_list)
        # logger.info('win_flag:')
        # logger.info(flag)
    else:
        stdin, stdout, stderr = s.exec_command('cat '+flagpath)
        flag = stdout.read().decode('unicode_escape')
    # logger.info('flag:', flag)
    s.close()
    return flag

if __name__ == '__main__':
    ip = '192.168.222.139'
    login = 'long'
    pwd = '123'
    logger.info('flag:\n{0}'.format(main(ip, login, pwd)))
