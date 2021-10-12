# Code to execute in an independent thread
# Create and launch a thread
from threading import Thread
import time
def countdown(n):
    while n > 0:
        print('T-minus', n)
        n -= 1
        time.sleep(5)

