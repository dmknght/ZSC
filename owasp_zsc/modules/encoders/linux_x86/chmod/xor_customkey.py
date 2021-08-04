import string
from owasp_zsc.new_cores.base_module import BaseModule, OptString

chars = string.digits + string.ascii_letters


class Encoder(BaseModule):
    key = OptString("", "Custom xor key")
    __info__ = {
        "description": "Add random encoding with key",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",  # routersploit module
        ),
    }

    def encode(self, shellcode):
        # start(type, shellcode, job)
        eax = str('0x0f909090')
        shellcode = shellcode.replace('0x0f', eax)
        while True:
            eax_1 = type.rsplit('xor_')[1][2:]
            eax_2 = "%x" % (int(eax, 16) ^ int(eax_1, 16))
            if '00' not in eax_1 and '00' not in eax_2 and len(eax_1) >= 7 and len(eax_2) >= 7:
                break
        eax = f'push ${str(eax)}'
        eax_xor = f'push $0x{eax_1}\npop %eax\npush $0x{eax_2}\npop %ebx\nxor %eax, %ebx\nshr $0x10, %ebx\nshr $0x8, %ebx\npush %ebx\n'
        shellcode = shellcode.replace(eax, eax_xor)
        ecx = str(shellcode.rsplit('\n')[10])
        ecx_value = str(shellcode.rsplit('\n')[10].rsplit()[1][1:])
        while True:
            ecx_1 = type.rsplit('xor_')[1][2:]
            ecx_2 = "%x" % (int(ecx_value, 16) ^ int(ecx_1, 16))
            if '00' not in ecx_1 and '00' not in ecx_2:
                break
        ecx_xor = f'push $0x{str(ecx_1)}\npop %ebx\npush $0x{str(ecx_2)}\npop %ecx\nxor %ecx, %ebx\npush %ebx\n_z3r0d4y_\n'
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
            if 'push $0x' in char:
                ebx = char.rsplit()[1][1:]
                ebx_1 = type.rsplit('xor_')[1][2:]
                ebx_2 = "%x" % (int(ebx, 16) ^ int(ebx_1, 16))
                command = f'push $0x{str(ebx_1)}\npop %ebx\npush $0x{str(ebx_2)}\npop %edx\nxor %ebx, %edx\npush %edx'
                middle = middle.replace(char, command)
        shellcode = start + middle + end
        return shellcode