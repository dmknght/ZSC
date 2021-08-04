import string
import binascii
import random
from owasp_zsc.new_cores.base_module import BaseModule

chars = string.digits + string.ascii_letters


class Encoder(BaseModule):
    __info__ = {
        "description": "Add random encoding with key",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",  # routersploit module
        ),
    }

    def encode(self, shellcode):
        eax = str('0x0f')
        while True:
            eax_1 = binascii.b2a_hex((''.join(random.choice(chars) for i in range(1))).encode('latin-1')).decode('latin-1')
            eax_1 = str('0') + str(eax_1[1])
            eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
            if eax > eax_1:
                if '00' not in str(eax_1) and '00' not in str(eax_2):
                    break
        eax = f'push ${str(eax)}'
        eax_xor = f'push $0x{eax_1}\npop %eax\npush $0x{eax_2}\npop %ebx\nxor %eax, %ebx\npush %ebx\n'
        shellcode = shellcode.replace(eax, eax_xor)
        ecx = str(shellcode.rsplit('\n')[8])
        ecx_value = str(shellcode.rsplit('\n')[8].rsplit()[1][1:])
        while True:
            ecx_1 = binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1')).decode('latin-1')
            ecx_2 = "%x" % (int(ecx_value, 16) ^ int(ecx_1, 16))
            if '00' not in str(ecx_1) and '00' not in str(ecx_2) and len(ecx_1) >= 7 and len(ecx_2) >= 7:
                break
        ecx_xor = f'push $0x{str(ecx_1)}\npop %ebx\npush $0x{str(ecx_2)}\npop %ecx\nxor %ecx, %ebx\npush %ebx\n_z3r0d4y_\n'
        shellcode = shellcode.replace(ecx, ecx_xor)
        n = 0
        start = ''
        middle = ''
        end = ''
        xor = 0
        for char in shellcode.rsplit('\n'):
            n += 1
            if xor == 0:
                if '_z3r0d4y_' not in char:
                    start += char + '\n'
                else:
                    xor = 1
            if xor == 1:
                if '_z3r0d4y_' not in char:
                    if '%esp, %ebx' not in char:
                        middle += char + '\n'
                    else:
                        xor = 2
            if xor == 2:
                end += char + '\n'
        for char in middle.rsplit('\n'):
            while True:
                if 'push $0x' in char:
                    ebx = char.rsplit()[1][1:]
                    ebx_1 = binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1')).decode('latin-1')
                    ebx_2 = "%x" % (int(ebx[2:], 16) ^ int(ebx_1, 16))
                    if '00' not in str(ebx_1) and '00' not in str(ebx_2) and len(ebx_2) >= 7 and len(ebx_1) >= 7 and '-' not in ebx_1:
                        ebx_2 = ebx_2.replace('-', '')
                        command = f'\npush $0x{str(ebx_1)}\npop %ebx\npush $0x{str(ebx_2)}\npop %edx\nxor %ebx, %edx\npush %edx\n'
                        middle = middle.replace(char, command)
                        break
                else:
                    break
        shellcode = start + middle + end
        return shellcode
