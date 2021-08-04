import binascii
import random
import string
from owasp_zsc.new_cores.base_module import BaseModule

chars = string.digits + string.ascii_letters


class Encoder(BaseModule):
    # Status: Tested the module for ASM compile. ASM code is good
    __info__ = {
        "description": "Add random encoding",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",
            "Nong Hoang Tu <dmknght@parrotsec.org>"
        ),
    }

    def encode(self, shellcode):
        eax = str('0x0f')
        while True:
            eax_1 = binascii.b2a_hex((''.join(random.choice(chars) for i in range(1))).encode('latin-1')).decode('latin-1')
            eax_1 = str('0') + str(eax_1[1])
            eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
            if eax > eax_1:
                if '00' not in str(eax_1) and '00' not in str(eax_2):
                    break
        eax = f"push ${str(eax)}"
        eax_add = f'push $0x{eax_1}\npop %eax\npush $0x{eax_2}\npop %ebx\nadd %eax, %ebx\npush %ebx\n'
        shellcode = shellcode.replace(eax, eax_add)
        ebx = str(shellcode.rsplit('\n')[8])
        ebx_value = str(shellcode.rsplit('\n')[8].rsplit()[1][1:])

        while True:
            ebx_1 = binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1')).decode(
                'latin-1')
            ebx_2 = "%x" % (int(ebx_value, 16) - int(ebx_1, 16))
            if '00' not in str(ebx_1) and '00' not in str(ebx_2) and \
                    int(len(ebx_1)) >= 7 and int(len(ebx_2)) >= 7 and '-' in ebx_2:
                break
        ebx_2 = ebx_2.replace('-', '')
        ebx_add = f"push $0x{str(ebx_1)}\npop %ebx\npush $0x{str(ebx_2)}\npop %ecx\nneg %ecx\n"
        ebx_add += "add %ecx, %ebx\npush %ebx\n_z3r0d4y_\n"
        shellcode = shellcode.replace(ebx, ebx_add)
        n = 0
        code_start = ''
        middle = ''
        end = ''
        add = 0
        for char in shellcode.rsplit('\n'):
            n += 1
            if add == 0:
                if '_z3r0d4y_' not in char:
                    code_start += char + '\n'
                else:
                    add = 1
            if add == 1:
                if '_z3r0d4y_' not in char:
                    if '%esp, %ebx' not in char:
                        middle += char + '\n'
                    else:
                        add = 2
            if add == 2:
                end += char + '\n'

        for char in middle.rsplit('\n'):
            while True:
                if 'push $0x' in char:
                    edx = char.rsplit()[1][1:]
                    edx_1 = binascii.b2a_hex(
                        (''.join(random.choice(chars) for i in range(4))).encode('latin-1')).decode('latin-1')
                    edx_2 = "%x" % (int(edx[2:], 16) - int(edx_1, 16))
                    if '00' not in str(edx_1) and '00' not in str(edx_2) and \
                            '-' in edx_2 and int(len(edx_2)) >= 7 and int(len(edx_1)) >= 7 and '-' not in edx_1:
                        edx_2 = edx_2.replace('-', '')
                        command = f"\npush $0x{str(edx_1)}\npop %ebx\npush $0x{str(edx_2)}\n"
                        command += "pop %edx\nneg %edx\nadd %ebx, %edx\npush %edx\n"
                        middle = middle.replace(char, command)
                        break
                else:
                    break
        shellcode = code_start + middle + end
        return shellcode
