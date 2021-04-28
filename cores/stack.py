"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
"""
import binascii
from cores.compatible import version
from cores.alert import *


def shellcoder(shellcode):
    n = 0
    xshellcode = '\\x'
    for w in shellcode:
        n += 1
        xshellcode += str(w)
        if n == 2:
            n = 0
            xshellcode += str('\\x')
    return xshellcode[:-2]


def st(data):
    return (binascii.b2a_hex(data[::-1].encode('latin-1'))).decode('latin-1')


def generate(data, register, gtype):
    length = len(data)
    if gtype == 'int':
        flag_8 = True
        try:
            data = hex(int(data, 8))
        except:
            flag_8 = False
        if not flag_8:
            try:
                data = hex(int(data, 16))
            except:
                error('hex or digit required!\nExit\n')
    if gtype == 'string':
        data = st(data)
    if length <= 3:
        if gtype == 'string':
            data = str('0x') + str(data)
        if len(data) % 2 != 0:
            data = data.replace('0x', '0x0')
        if len(data) == 8:
            data += f"90\npop {register}\nshr $0x8,{register}\npush {register}\n"
        if len(data) == 6:
            data += f"9090\npop {register}\nshr $0x10,{register}\npush {register}\n"
        if len(data) == 4:
            data += f"909090\npop {register}\nshr $0x10,{register}\nshr $0x8,{register}\npush {register}\n"
        data = str('push $') + str(data)
    if length >= 4:
        if gtype == 'int':
            data = data[2:]
        stack_content = data
        shr_counter = len(stack_content) % 8
        shr = None
        if shr_counter == 2:
            shr = f"\npop {register}\nshr    $0x10,{register}\nshr    $0x8,{register}\npush {register}\n"
            stack_content = f"{stack_content[0:2]}909090{stack_content[2:]}"
        if shr_counter == 4:
            shr = f"\npop {register}\nshr    $0x10,{register}\npush {register}\n"
            stack_content = f"{stack_content[0:4]}9090{stack_content[4:]}"
        if shr_counter == 6:
            shr = f"\npop {register}\nshr    $0x8,{register}\npush {register}\n"
            stack_content = f"{stack_content[0:6]}90{stack_content[6:]}"
        zshr = shr
        m = int(len(stack_content))
        n = int(len(stack_content) / 8)
        file_shellcode = ''
        if (len(stack_content) % 8) == 0:
            shr_n = 0
            r = ''
            while n != 0:
                if shr:
                    shr_n += 1
                    zx = m - 8
                    file_shellcode = f"push $0x{str(stack_content[zx:m])}\n{file_shellcode}"
                    m -= 8
                    n = n - 1
                    shr = None
                if not shr:
                    shr_n += 1
                    zx = m - 8
                    file_shellcode = f"push $0x{str(stack_content[zx:m])}\n{file_shellcode}"
                    m -= 8
                    n = n - 1
            if not zshr:
                file_z = file_shellcode
            if zshr:
                rep1 = file_shellcode[:16]
                rep2 = rep1 + zshr
                file_z = file_shellcode.replace(rep1, rep2)
        data = file_z
    return data


def to_hex(value):
    if len(value) == 1:
        return '0' + value
    return value
