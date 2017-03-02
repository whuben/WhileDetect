#!/usr/bin/env python2.7
#-*-coding:utf-8 -*-
'''
written by ben
2015/11/09
'''
from capstone import *
from capstone.x86 import *
from ctypes import *
from typedef import *

class Dissamble(object):
    'dissamble the binary for exec section'
    def __init__(self,elf,shdr):
        print "#starting to dissamble the bianry"
        self.__elf=bytearray(elf)
        self.__shdr=shdr
        self.dissamble_dict={}    #the dissambled section dict
        self.base_addr=None       #the base address of elf when loading
        self.__Dissamble()
        #self.Output()

    def __Dissamble(self):
        shdr_addr_start=-1
        shdr_addr_end=-1
        for i in range(len(self.__shdr)):
            #dissamble the the executed sections and record the address boundary
            if self.__shdr[i].sh_flags==ELFSectionflags.SHF_EXECINSTR+ELFSectionflags.SHF_ALLOC:
                shdr_addr_start=self.__shdr[i].sh_offset
                shdr_addr_end=shdr_addr_start+self.__shdr[i].sh_size
                shdr_virtual_addr=self.__shdr[i].sh_addr
                #exclude the .plt section
                if self.__shdr[i].section_name=='.plt':
                    continue
                shdr_bytes=self.__elf[shdr_addr_start:shdr_addr_end]
                md=Cs(CS_ARCH_X86,CS_MODE_64)
                md.detail=True
                dissamble_ins=md.disasm(str(shdr_bytes),shdr_virtual_addr)
                self.dissamble_dict[str(self.__shdr[i].section_name)]=list(dissamble_ins)
                
