#!/usr/bin/env python2.7
#-*-coding:utf-8 -*-
'''
written by ben
2017/02/27
'''
from capstone import *
from capstone.x86 import *
from ctypes import *
from typedef import *
from elf import *
from dissamble import *
from threadpool import *

JUMP_MAX_DITANCE = 0xff
MAX_NUM_THREAD = 20

class Searchwhile(object):
    def __init__(self,elf):
        self.__elfparse = Elf64_Parse(elf)
        self.__dissamble = Dissamble(elf,self.__elfparse.GetShdr())
        self.__dissamble_dict = self.__dissamble.dissamble_dict
        self.__jump_list = []   #format [ [key,target_addr,ins.address] ]
        self.__while_list = []
        self.__FindJump()
        self.__StartThearding()

    def __FindJump(self):
        for key in self.__dissamble_dict:
            for ins in self.__dissamble_dict[key]:
                if ins.id == X86_INS_JMP and ins.operands[0].type==X86_OP_IMM:  # jump imm
                    target_addr = ins.operands[0].value.imm
                    if  target_addr < ins.address and ins.address-target_addr<=JUMP_MAX_DITANCE:
                        self.__jump_list.append([key,target_addr,ins.address])

    def __FindWhile(self,jump_list):
        start_flag = False
        find_flag = True
        for ins in self.__dissamble_dict[jump_list[0]]:
            if ins.address==jump_list[1]:
                start_flag = True
                continue
            if ins.address==jump_list[2]:
                break
            if start_flag==True and ins.id>=X86_INS_JAE and ins.id<=X86_INS_JS: #values between 255-274 are instructions with a type of jump
                ins_target_addr = jump_list[1]
                if ins.operands[0].type==X86_OP_IMM:   #jmp imm
                    ins_target_addr = ins.operands[0].value.imm
                elif ins.operands[0].type ==X86_OP_MEM:   #jmp qword[rip+disp]
                    if ins.operands[0].value.mem.base==X86_REG_RIP:
                        ins_target_addr = ins.operands[0].value.mem.disp+ins.address+ins.size
                if ins_target_addr>jump_list[2] or ins_target_addr<jump_list[1]:
                    find_flag = False
                    break
        if find_flag:
            print "[WHILE] 0x%x---0x%x"%(jump_list[1],jump_list[2])
        # else:
        #     print "[FALSE] 0x%x---0x%x"%(jump_list[1],jump_list[2])

    def __StartThearding(self):
        #using thread pool to find the while true instruction models
        pool = ThreadPool(MAX_NUM_THREAD)
        requests = makeRequests(self.__FindWhile,self.__jump_list)
        for req in requests:
            pool.putRequest(req)
        pool.wait()





        
