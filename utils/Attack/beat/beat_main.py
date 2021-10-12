import asyncio
import test
# import beat_client

import requests
import time
import threading
import json

def xintiao():
    global timer
    timer = threading.Timer(5,xintiao)
    data = { 
        'Content-Type': 'application/json',
        'team_token' : "M6ADxU6ARWunKMjcNV3EnbBSwtE9wercsdSeyXNRunjxV" } 

    response = requests.post("http://139.9.116.151/api/v1/jeopardy/admin/heart_beat_report", json=data)

    # print(response)
    # print(response.text)
    Write(str(response)+":"+str(response.text))
    timer.start()

# 写日志  输入log_data 
def Write(log_data):
    log_file = time.strftime("log_%m%d-%H.txt", time.localtime())
    with open("/home/kali/HFBOT/HFBOT/utils/Attack/beat/log/%s"%(log_file), "a") as f:
        log_data = str(log_data)
        localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        f.write("%s: %s"%(localtime, str(log_data)))
        f.write('\n')
        f.close()


if __name__ == '__main__':
    # asyncio.run(main())
    xintiao()
