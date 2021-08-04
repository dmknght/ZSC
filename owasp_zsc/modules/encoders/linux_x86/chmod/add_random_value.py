import string
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
        # value = type.rsplit('add_')[1][2:]
        eax = str('0x0f909090')
        while True:
            eax_1 = type.rsplit('add_')[1][2:]  # def start(type, shellcode, job):
            eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
            if '00' not in str(eax_1) and '00' not in str(eax_2) and '-' in eax_2:
                eax_2 = eax_2.replace('-', '')
                break
        eax = 'push $0x0f'
        eax_xor = f'push $0x{eax_1}\npop %eax\npush $0x{eax_2}\npop %ebx\nneg %ebx\nadd %eax, %ebx\nshr $0x10, %ebx\nshr $0x08, %ebx\npush %ebx\n'
        shellcode = shellcode.replace(eax, eax_xor)
        ecx = str(shellcode.rsplit('\n')[11])
        ecx_value = str(shellcode.rsplit('\n')[11].rsplit()[1][1:])
        while True:
            ecx_1 = type.rsplit('add_')[1][2:]
            ecx_2 = "%x" % (int(ecx_value, 16) - int(ecx_1, 16))
            if '00' not in str(ecx_1) and '00' not in str(ecx_2) and len(ecx_1) >= 7 and len(ecx_2) >= 7:
                break
        ecx_2 = ecx_2.replace('-', '')
        ecx_xor = f'push $0x{str(ecx_1)}\npop %ebx\npush $0x{str(ecx_2)}\npop %ecx\nneg %ecx\nadd %ecx, %ebx\npush %ebx\n_z3r0d4y_\n'
        shellcode = shellcode.replace(ecx, ecx_xor)
        n = 0
        start = ''
        middle = ''
        end = ''
        add = 0
        for char in shellcode.rsplit('\n'):
            n += 1
            if add == 0:
                if '_z3r0d4y_' not in char:
                    start += char + '\n'
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
            t = True
            while t:
                if 'push $0x' in char:
                    ebx = char.rsplit()[1][1:]
                    ebx_1 = type.rsplit('add_')[1][2:]
                    ebx_2 = "%x" % (int(ebx[2:], 16) - int(ebx_1, 16))
                    if '00' not in str(ebx_1) and '00' not in str(ebx_2) and len(ebx_2) >= 7 and len(ebx_1) >= 7:
                        ebx_2 = ebx_2.replace('-', '')
                        command = f'\npush $0x{str(ebx_1)}\npop %ebx\npush $0x{str(ebx_2)}\npop %edx\nadd %ebx, %edx\npush %edx\n'
                        middle = middle.replace(char, command)
                        t = False
                else:
                    t = False
        shellcode = start + middle + end
        return shellcode
