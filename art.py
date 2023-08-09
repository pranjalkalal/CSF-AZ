import time
import sys
from printy import printy
from pyfiglet import Figlet


def print1():
    custom_figlet = Figlet(font='epic')
    ascii_art = custom_figlet.renderText('CSF-Az')
    printy(ascii_art, 'yBI')
    message = 'starting the auditing framework...'
    for x in range(len(message)):
        sys.stdout.write('\r' + '[*] ' + message[:x] + message[x:].capitalize())
        sys.stdout.flush()
        time.sleep(0.1)
    print('\n')


if __name__ == '__main__':
    print1()
