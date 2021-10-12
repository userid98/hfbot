import logging, os

class color:
    def __init__(self) -> None:
        
        self.PURPLE = '\033[95m'
        self.CYAN = '\033[96m'
        self.DARKCYAN = '\033[36m'
        self.BLUE = '\033[94m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.RED = '\033[91m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'
        self.END = '\033[0m'
        # log
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler("host.log", mode='a')
        formatter = logging.Formatter("%(asctime)s -  %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        # log

    def print_color(self,s,c='\033[92m'):
        self.logger.info(c + s+ self.END)