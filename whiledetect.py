#!/usr/bin/env python2.7
#-*-coding:utf-8 -*-
'''
written by ben
2017/03/01
'''
from searchwhile import *
import sys

def main():
    '$python whiledetect.py bin_path'
    if len(sys.argv)<2:
        print "please set the binary path!"
        exit(1)
    #get the binary path
    bin_path=sys.argv[1]
    try:
        fd_bin=open(bin_path,"rb")
    except IOError as err:
        print "IOError:"+str(err)
        exit(1)
    bin_raw=fd_bin.read()
    fd_bin.close()
    #time1=time.time()  #the start time
    # call the rewrite class to randomize the binary
    while_detect = Searchwhile(bin_raw)
    while_detect.printWhile()

if __name__ == '__main__':
    main()
