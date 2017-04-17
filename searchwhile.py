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

JUMP_MAX_DITANCE = 0xff
MAX_NUM_THREAD = 20

class Searchwhile(object):
    def __init__(self,elf):
        self.__elfparse = Elf64_Parse(elf)
        self.__dissamble = Dissamble(elf,self.__elfparse.GetShdr())
        self.__dissamble_dict = self.__dissamble.dissamble_dict
        self.__transfer_dict = {}  #dict for recording transfer instructions
        self.__while_dict = {} #dict for recording the while loop
        self.__FindJump()
 
    def __FindJump(self):
        for key in self.__dissamble_dict:
            for ins in self.__dissamble_dict[key]:
                if (ins.id>=X86_INS_JAE and ins.id<=X86_INS_JS) or ins.id==X86_INS_RET:  #jump/ret instructions
                    key_address = ins.address
                    value_ins = ins 
                    self.__transfer_dict[key_address]=value_ins
        key_sort = sorted(self.__transfer_dict.keys())
        for i in range(len(key_sort)):
            trans_ins = self.__transfer_dict[key_sort[i]]
            if trans_ins.id==X86_INS_JMP and trans_ins.operands[0].type==X86_OP_IMM: #jmp imm
                target_addr = trans_ins.operands[0].imm
                if target_addr<trans_ins.address: #jump to above
                    if i==0: #handle the first jmp instrucion
                        self.__while_dict[trans_ins.address] = trans_ins
                    else:
                        if target_addr>key_sort[i-1]:
                            self.__while_dict[trans_ins.address] = trans_ins
                        else :
                            back_index = i
                            while target_addr<=key_sort[back_index-1] and back_index>=1:
                                back_index-=1
                            while_flag = True
                            for j in range(back_index,i):                               
                                pre_ins = self.__transfer_dict[key_sort[j]]
                                if pre_ins.id==X86_INS_RET:
                                    while_flag = False
                                    break
                                if pre_ins.id>=X86_INS_JAE and pre_ins.id<=X86_INS_JS: #jump
                                    operand_type = pre_ins.operands[0].type
                                    pre_target_addr = 0x00
                                    if operand_type==X86_OP_REG:   #jmp reg
                                        while_flag = False
                                        break
                                    elif operand_type==X86_OP_IMM: #jmp imm
                                        pre_target_addr = pre_ins.operands[0].imm
                                    elif operand_type==X86_OP_MEM and pre_ins.operands[0].value.mem.base==X86_REG_RIP: #jmp qword[rip+disp]
                                        pre_target_addr = pre_ins.operands[0].value.mem.disp+pre_ins.address+pre_ins.size
                                    if pre_target_addr==0x00 or pre_target_addr>trans_ins.address or pre_target_addr<target_addr:
                                        while_flag = False
                                        break
                            if while_flag:
                                self.__while_dict[trans_ins.address]=trans_ins
    def printWhile(self):
        print "---------WHILE INFO---------"
        key_while = sorted(self.__while_dict.keys())
        for key_addr in key_while:
            ins = self.__while_dict[key_addr]
            print "[0x%x]:\t%s\t%s\n"%(ins.address,ins.mnemonic,ins.op_str)

        
