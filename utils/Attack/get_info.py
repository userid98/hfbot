import requests
import json
import sys
import logging
import os
# log
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(os.path.basename(__file__)[:-3]+".log", mode='a')
formatter = logging.Formatter("%(asctime)s -  %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# log

global task_num
global task_list

task_num = -1
task_list = []

task_info = []

def get_taskhash(event_hash,team_token):
    global task_num
    global task_list

    url = "http://139.9.116.151/api/v1/jeopardy/web/event_tasks?event_hash=%s.event&team_token=%s"%(event_hash,team_token)
    web = requests.get(url)
    result = web.text
    text = json.loads(result)
    #logger.info(text)
    task_num = text['total']
    task_list = text['data']['task_hash']
    return result

def get_taskinfo(task_hash,team_token):
    global task_info

    url = "http://139.9.116.151/api/v1/jeopardy/web/event_tasks/challenge_information?task_hash=%s&team_token=%s"%(task_hash,team_token)
    web = requests.get(url)
    result = web.text
    text = json.loads(result)
    #logger.info(text)
    task_info.append("%s :%s"%(text['task_hash'],text['network']))
    return result

def submit_flag(flag,event_hash,team_token):
    global task_info

    url = "http://139.9.116.151/api/v1/jeopardy/web/flags?evt=%s.event"%(event_hash)
    jsonheaders = {'Content-Type':'application/json'}
    data = {"answer": "%s"%(flag), "team_token": "%s"%(team_token)}
    web = requests.request("post",url,json=data,headers=jsonheaders)

    result = web.text
    text = json.loads(result)
    logger.info(text)
    #task_info.append("%s :%s"%(text['task_hash'],text['network']))
    return result


if __name__ == "__main__":

    h = '''
 ('-. .-.          .-. .-')                .-') _    
( OO )  /          \\  ( OO )              (  OO) )   
,--. ,--.   ,------.;-----.\\  .-'),-----. /     '._  
|  | |  |('-| _.---'| .-.  | ( OO'  .-.  '|'--...__) 
|   .|  |(OO|(_\\    | '-' /_)/   |  | |  |'--.  .--' 
|       |/  |  '--. | .-. `. \\_) |  |\\|  |   |  |    
|  .-.  |\\_)|  .--' | |  \\  |  \\ |  | |  |   |  |    
|  | |  |  \\|  |_)  | '--'  /   `'  '-'  '   |  |    
`--' `--'   `--'    `------'      `-----'    `--'    
  usage:
  get_task_info:  python3 HFBOT.py event_hash team_token
  submit_flag:    python3 HFBOT.py event_hash team_token flag 

  example:        python3 HFBOT.py 1b8f1d6f-2496-464d-8525-1acba83a08b8 M6ADxU6ARWunKMjcNV3EnbBSwtE9wercsdSeyXNRunjxV
                  python3 HFBOT.py 1b8f1d6f-2496-464d-8525-1acba83a08b8 M6ADxU6ARWunKMjcNV3EnbBSwtE9wercsdSeyXNRunjxV flag{bu1dJNnj4pZ6kBYXi0Jdp1fGOmAeXods}
        '''
    if len(sys.argv) == 1:
        logger.info(h)
        exit
    
    elif len(sys.argv) == 3:
        event_hash = sys.argv[1]
        team_token = sys.argv[2]
        get_taskhash(event_hash,team_token)
        logger.info("task_num: %s\n"%task_num)
        for i in task_list:
            get_taskinfo(i,team_token)
        #logger.info(task_info)
        for j in task_info:
            logger.info(j)
    elif len(sys.argv) == 4:
        event_hash = sys.argv[1]
        team_token = sys.argv[2]
        flag = sys.argv[3]
        submit_flag(flag,event_hash,team_token)

    else:
        logger.info(h)
        exit
