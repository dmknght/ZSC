from owasp_zsc.new_cores.base_module import BaseModule


class Encoder(BaseModule):
    # Status: Tested the module for ASM compile. ASM code is good
    __info__ = {
        "description": "Add random encoding",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",  # routersploit module
        ),
    }

    def encode(self, shellcode):
        eax = str('0x0f')
        eax_2 = '%x' % (int('0f', 16) - int('01', 16))
        eax = f'push ${str(eax)}'
        eax_inc = f'push $0x{eax_2}\npop %eax\ninc %eax\npush %eax'
        shellcode = shellcode.replace(eax, eax_inc)
        ecx = str(shellcode.rsplit('\n')[5])
        ecx_value = str(shellcode.rsplit('\n')[5].rsplit()[1][1:])
        ecx_2 = "%x" % (int(ecx_value, 16) - int('01', 16))
        ecx_inc = f'push $0x{str(ecx_2)}\npop %ebx\ninc %ebx\npush %ebx\n_z3r0d4y_\n'
        shellcode = shellcode.replace(ecx, ecx_inc)
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
                ebx_2 = "%x" % (int(ebx, 16) - int('01', 16))
                command = f'push $0x{str(ebx_2)}\npop %ebx\ninc %ebx\npush %ebx'
                middle = middle.replace(char, command)
        shellcode = start + middle + end
        return shellcode