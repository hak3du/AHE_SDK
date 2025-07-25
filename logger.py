import logging
import os
from colorama import init, Fore, Style

init(autoreset=True)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    # Custom keywords to color-code messages
    KEYWORD_COLORS = {
        'SECURITY': Fore.MAGENTA + Style.BRIGHT,
        'TRACE': Fore.BLUE,
        'INTEGRITY': Fore.CYAN,
        'ZERO-KNOWLEDGE': Fore.GREEN + Style.BRIGHT,
        'AUDIT': Fore.YELLOW,
    }

    def format(self, record):
        msg = super().format(record)
        # Color by level
        color = self.COLORS.get(record.levelname, '')
        msg = color + msg + Style.RESET_ALL
        
        # Color by keywords inside the message
        for keyword, kw_color in self.KEYWORD_COLORS.items():
            if keyword in msg:
                msg = msg.replace(keyword, kw_color + keyword + Style.RESET_ALL)
        return msg

logger = logging.getLogger("AHE_SDK")
logger.setLevel(logging.DEBUG)  # Capture all levels

file_handler = logging.FileHandler("logs/ahe_sdk.log")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_formatter = ColorFormatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)