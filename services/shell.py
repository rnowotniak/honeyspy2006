#!/usr/bin/env python
# HoneySpy -- advanced honeypot environment
# Copyright (C) 2005  Robert Nowotniak
# Copyright (C) 2005  Michal Wysokinski
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


#
# XXX
# THIS CODE NEEDS SERIOUS REFACTORING OR NEEDS TO BE REWRITTEN
#

from twisted.internet import protocol
from random import randint
from os import  fdopen, fsync, getpid,kill
import os
import sys

### Import Polish locale ###
# import locale
# locale.setlocale(locale.LC_ALL, 'polish')
############################

uname = 'FreeBSD freebsd.sober.da.ru 6.0-RELEASE FreeBSD 6.0-RELEASE #0: Thu Nov  3 09:36: ' \
+ '13 UTC 2005     root@x64.samsco.home:/usr/obj/usr/src/sys/GENERIC  i386\r\n'
prompt = '[%(cwd)s]$ '



############################################
# Definicje prostych funkcji komend powloki
#
def uptime(shell, args):
    return ' %d:%d:%d up  %d days, %d users,   load average: %d.00, %d.00, %d.00\r\n' \
        % (randint(0,23), randint(0,60), randint(0,60), randint(0,100), \
                randint(0,30), randint(0,30), randint(0,30), randint(0,30));

def exit(shell, args):
    os.kill(shell.getParentPID(),9)

def cd(shell, args):
    if len(args) > 1:
        shell.cwd = args[1]
    else:
        shell.cwd = '~'
    return ''

def echo(shell, args):
    return ' '.join(args[1:]) + '\r\n'

def pwd(shell, args):
    return shell.cwd + '\r\n'

def wget(shell, args):
    if len(args) > 1:
        return """
Length: 99,342 \r
\r
    0K .......... .......... .......... .......... .......... 51%  286.52 KB/s\r
   50K .......... .......... .......... .......... .......   100%  619.29 KB/s\r
\r
23:10:46 (387.40 KB/s) - file saved [99342/99342]\r
"""
    else:
        return """
wget: missing URL\r
Usage: wget [OPTION]... [URL]...\r
\r
"""
    
def ls(shell, args):
    if shell.cwd == '/':
        return """drwxr-xr-x   2 root  wheel  1024  1 sty 14:59 bin/\r
drwxr-xr-x   5 root  wheel   512  1 sty 23:05 boot/\r
drwxr-xr-x   2 root  wheel   512 29 gru 18:56 cdrom/\r
lrwxr-xr-x   1 root  wheel    10 29 gru 19:06 compat@ -> usr/compat\r
dr-xr-xr-x   4 root  wheel   512  1 sty  1970 dev/\r
drwxr-xr-x   2 root  wheel   512 29 gru 18:56 dist/\r
-rw-------   1 root  wheel  4096  1 sty 23:29 entropy\r
drwxr-xr-x  18 root  wheel  2048  1 sty 13:27 etc/\r
lrwxrwxrwx   1 root  wheel     8 29 gru 19:16 home@ -> usr/home\r
drwxr-xr-x   3 root  wheel  1024 29 gru 18:56 lib/\r
drwxr-xr-x   2 root  wheel   512 29 gru 18:56 libexec/\r
drwxr-xr-x   3 root  wheel   512 31 gru 02:30 mnt/\r
dr-xr-xr-x   2 root  wheel   512  3 lis 09:09 proc/\r
drwxr-xr-x   2 root  wheel  2560 29 gru 18:56 rescue/\r
drwxr-xr-x   3 root  wheel   512  1 sty 23:05 root/\r
drwxr-xr-x   2 root  wheel  2560 29 gru 18:56 sbin/\r
lrwxrwxrwx   1 root  wheel    11 29 gru 18:56 sys@ -> usr/src/sys\r
drwxrwxrwt  10 root  wheel   512  8 sty 22:49 tmp/\r
drwxr-xr-x  38 root  wheel  1024 31 gru 12:19 usr/\r
lrwxr-xr-x   1 root  wheel     7 31 gru 12:18 var@ -> usr/var\r
"""
    else:
        return """total 8\r
drwx------  2 rob  rob  4096 Jan  8 23:17 .\r
drwxrwxrwt  6 root root 4096 Jan  8 23:17 ..\r
"""

commands = {
    'ls'     : ls,
    'wget'   : wget,
    'uptime' : uptime,
    'uname'  : uname,
    'exit'   : exit,
    'cd'     : cd,
    'logout' : exit,
    'echo'   : echo,
    'pwd'    : pwd,
    'mount'  : """/dev/ad0s4a on / (ufs, local)\r
devfs on /dev (devfs, local)\r
/dev/ad0s4d on /tmp (ufs, local, soft-updates)\r
/dev/ad0s4e on /usr (ufs, local, soft-updates)\r
/dev/ad0s1 on /mnt/linux (ext2fs, local)\r
/dev/ad0s3 on /mnt/linux/home (ext2fs, local)\r
""",
    'w'      : """22:53  up 4 mins, 2 users, load averages: 0,03 0,16 0,09\r
USER             TTY      FROM              LOGIN@  IDLE WHAT\r
root              v0       -                22:49       3 csh\r
rob               p0       :0.0             22:49       - zsh\r
""",
    'who'    : """rob              ttyv0     8 Jan 22:49\r
root             ttyp0     8 Jan 22:49 (:0.0)\r
""",
    'ps'     : """USER    PID %CPU %MEM   VSZ   RSS  TT  STAT STARTED      TIME COMMAND\r
    root     11 98,9  0,0     0     8  ??  RL   22:49     3:59,64 [idle]\r
    root      0  0,0  0,0     0     0  ??  WLs  22:49     0:00,00 [swapper]\r
    root      1  0,0  0,1   724   356  ??  ILs  22:49     0:00,01 /sbin/init --\r
    root      2  0,0  0,0     0     8  ??  DL   22:49     0:00,02 [g_event]\r
    root      3  0,0  0,0     0     8  ??  DL   22:49     0:00,08 [g_up]\r
    root      4  0,0  0,0     0     8  ??  DL   22:49     0:00,10 [g_down]\r
    root      5  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [thread taskq]\r
    root      6  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [kqueue taskq]\r
    root      7  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [acpi_task0]\r
    root     34  0,0  0,0     0     8  ??  WL   22:49     0:00,00 [swi6: task queue]\r
    root     35  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [cbb0]\r
    root     36  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [cbb1]\r
    root     37  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [usb0]\r
    root     38  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [usbtask]\r
    root     39  0,0  0,0     0     8  ??  DL   22:49     0:00,03 [acpi_thermal]\r
    root     40  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [fdc0]\r
    root     41  0,0  0,0     0     8  ??  WL   22:49     0:00,00 [swi0: sio]\r
    root     42  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [pagedaemon]\r
    root     43  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [vmdaemon]\r
    root     44  0,0  0,0     0     8  ??  DL   22:49     0:02,14 [pagezero]\r
    root     45  0,0  0,0     0     8  ??  DL   22:49     0:00,00 [bufdaemon]\r
    root     46  0,0  0,0     0     8  ??  DL   22:49     0:00,01 [syncer]\r
    root     52  0,0  0,0     0     8  ??  DL   22:49     0:00,01 [schedcpu]\r
    root    154  0,0  0,3  1172   644  ??  Is   22:49     0:00,00 adjkerntz -i\r
    root    262  0,0  0,1   500   352  ??  Is   22:49     0:00,00 /sbin/devd\r
    root    291  0,0  0,3  1296   876  ??  Ss   22:49     0:00,02 /usr/sbin/syslogd -s\r
    root    366  0,0  0,3  1208   772  ??  Ss   22:49     0:00,00 /usr/sbin/usbd\r
    smmsp   435  0,0  1,0  3424  2560  ??  Is   22:49     0:00,00 sendmail: Queue runner@00:30:00 for /var/spool/clientmqueue (sendmail\r
    root    447  0,0  0,4  1312  1032  ??  Ss   22:49     0:00,01 /usr/sbin/cron -s\r
    root    469  0,0  0,3  1208   716  ??  Is   22:49     0:00,00 /usr/sbin/moused -p /dev/psm0 -t auto\r
    root    503  0,0  0,5  1616  1284  v0  Is   22:49     0:00,03 login [pam] (login)\r
    rob     511  0,0  0,8  3180  1996  v0  I    22:49     0:00,03 -bash (bash)\r
    rob     520  0,0  0,5  1992  1284  v0  I+   22:49     0:00,01 xinit\r
    root    521  0,0  5,7 23352 14496  v0  R    22:49     0:04,74 X :0 (Xorg)\r
    rob     524  0,0  1,4  5240  3600  v0  I    22:49     0:00,36 fvwm\r
    root    534  0,0  1,7  5100  4228  v0  S    22:49     0:00,25 xterm (xterm-static)\r
    root    504  0,0  0,4  1268   932  v1  Is+  22:49     0:00,00 /usr/libexec/getty Pc ttyv1\r
    root    509  0,0  0,4  1268   932  v6  Is+  22:49     0:00,00 /usr/libexec/getty Pc ttyv6\r
    root    510  0,0  0,4  1268   932  v7  Is+  22:49     0:00,00 /usr/libexec/getty Pc ttyv7\r
    rob     535  0,0  0,9  3196  2156  p0  Ss   22:49     0:00,04 bash\r
    rob     547  0,0  0,8  3188  2136  p1  Ss   22:53     0:00,02 /usr/local/bin/bash -i\r
    rob     551  0,0  0,4  1416  1020  p1  R+   22:53     0:00,00 ps auxfw\r
""",
    'id'     : 'uid=1005(john) gid=1005(john) groups=20(dialout),24(cdrom),25(floppy),29(audio),44(video),46(plugdev),50(staff),104(nvram)\r\n',
    'groups'     : 'john dialout cdrom floppy audio video plugdev staff nvram\r\n',
    ''       : '',
}

# Funkcja uzywana do logowania danych do HoneySpy'a
#

#
# Our fake shell
#
class ShellSimulationProtocol(protocol.Protocol):
    LOG = None 
    parentPID = None

    def __init__(self,pid):
        self.cmdline = ''
        self.cwd = '/tmp'
        self.prompt = prompt
        self.LOG = fdopen(3, 'w')
        self.parentPID = pid

    def getParentPID(self):
        return self.parentPID

    def log(self, msg):
        self.LOG.write('['+str(getpid())+'] ' + msg + '\r\n')
        self.LOG.flush()

    def logCommand(self,msg):
        self.LOG.write('['+str(getpid())+'] command: ' + msg + '\r\n')
        self.LOG.flush()

    def executeCommand(self, cmdline):
        self.logCommand(cmdline)
        global commands
        tokens = cmdline.split()
        if len(tokens) == 0:
            tokens = ['']
        if tokens[0] in commands:
            result = commands[tokens[0]]
            if type(result) == type(''):
                data = result
            else:
                data = result(self, tokens)
        else:
            data = 'bash: '+tokens[0]+': command not found\r\n'
        return data;

    def printPrompt(self):
        self.transport.write(prompt % {'cwd':self.cwd});
    
    def returnPrompt(self):
        return prompt % {'cwd':self.cwd} 

    def connectionMade(self):
        self.printPrompt()
    
    def zeroCommand(self):
        self.cmdline = ""
       
    def dataReceived(self, data):
        if data == '\x03': #^C
            self.executeCommand('exit')
        elif data == '\r':
            data = self.executeCommand(self.cmdline)
            self.transport.write('\r\n' + data)
            self.printPrompt()
            self.zeroCommand()
        else:
             self.cmdline += data
             self.transport.write(data)


