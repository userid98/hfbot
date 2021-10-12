import os
import json
import logging

def poc_test(vul,address,ip,port,success):
    target="http://"+ip+":"+port
    command="python3 "+address+" -u "+target
    process = os.popen(command) # return file
    output = process.read()
    process.close()
    if output.find(success)!=-1:
        logger.info("存在漏洞"+vul)
        return True
    else:
        logger.info("不存在漏洞"+vul)
        return False
    
def python_exp(vul,address,ip,port,command):
    logger.info("exp vul:"+vul["name"])
    exp=vul["exptools"]
    paras=exp["parameters"]
    
# log
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.basename(__file__)[:-3]+".log", mode='a')
formatter = logging.Formatter("%(asctime)s -  %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# log



with open("tools/vul_tools.json", 'r') as f:
    vulhub = json.loads(f.read())

vul=vulhub["vuls"][0]["name"]
address=vulhub["vuls"][0]["poctools"]["address"]
success=vulhub["vuls"][0]["poctools"]["success"]
poc_test(vul,address,"192.168.192.156","8080",success)